"""Unit tests for policy profiles (advisory / balanced / strict).

Balanced is asserted by `test_policy.py` (it is the historic default).
This file covers the two new profiles and the threshold differences.
"""

from __future__ import annotations

from secureflow.config import PolicyConfig
from secureflow.policy import decide


def _finding(**kw) -> dict:
    base = {
        "id": "x" * 16,
        "source": "semgrep",
        "title": "thing",
        "description": "thing",
        "severity": "low",
        "confidence": 0.7,
        "cwe": [], "owasp": [], "mitre_attack": [], "cve": [],
        "reachability": "unknown", "false_positive": False,
        "patch_status": "none",
    }
    base.update(kw)
    return base


# ----- advisory profile -----

def test_advisory_never_fails_on_critical_secret() -> None:
    f = _finding(source="gitleaks", severity="critical", title="AWS key")
    d = decide([f], policy=PolicyConfig(profile="advisory"))
    assert d.status == "WARN"
    assert any("advisory profile" in r for r in d.reasons)


def test_advisory_never_fails_on_high_impact_sast() -> None:
    f = _finding(
        source="semgrep", severity="high", confidence=0.9,
        rule_id="python.lang.security.sqli", title="SQL injection",
    )
    d = decide([f], policy=PolicyConfig(profile="advisory"))
    assert d.status == "WARN"


def test_advisory_preserves_pass_when_no_findings() -> None:
    d = decide([], policy=PolicyConfig(profile="advisory"))
    assert d.status == "PASS"


def test_advisory_keeps_blocking_reasons_in_report() -> None:
    f = _finding(source="gitleaks", severity="critical", title="AWS key")
    d = decide([f], policy=PolicyConfig(profile="advisory"))
    # The underlying reason is preserved so reviewers know what *would* have
    # blocked under balanced/strict.
    assert any("AWS key" in r for r in d.reasons)


# ----- strict profile -----

def test_strict_fails_on_ai_high_at_0_85() -> None:
    """Balanced WARNs on AI-high; strict FAILs at confidence >= 0.85."""
    f = _finding(source="ai_discovery", severity="high", confidence=0.86, title="logic flaw")

    bal = decide([f], policy=PolicyConfig(profile="balanced"))
    assert bal.status == "WARN"

    strict = decide([f], policy=PolicyConfig(profile="strict"))
    assert strict.status == "FAIL"


def test_strict_fails_on_ai_critical_at_0_75() -> None:
    """Balanced needs 0.85; strict lowers to 0.75."""
    f = _finding(source="ai_discovery", severity="critical", confidence=0.78, title="auth bypass")

    bal = decide([f], policy=PolicyConfig(profile="balanced"))
    assert bal.status == "WARN"

    strict = decide([f], policy=PolicyConfig(profile="strict"))
    assert strict.status == "FAIL"


def test_strict_fails_threat_model_at_0_70() -> None:
    """Threat model FAIL recommendations block at 0.70+ in strict, 0.80+ otherwise."""
    tm = {
        "title": "Missing auth on admin route",
        "change_type": "new_route",
        "severity": "high",
        "confidence": 0.72,
        "suggested_decision": "FAIL",
        "mitigations": ["Add auth middleware"],
    }

    bal = decide([], policy=PolicyConfig(profile="balanced"), threat_model_findings=[tm])
    assert bal.status == "WARN"

    strict = decide([], policy=PolicyConfig(profile="strict"), threat_model_findings=[tm])
    assert strict.status == "FAIL"


def test_strict_fails_high_dep_with_fix_available() -> None:
    """Strict blocks high-severity *direct* deps with a fix; balanced WARNs."""
    f = _finding(
        source="grype", severity="high", title="CVE-2024-9999 in pkg 1.0.0",
        recommendation="Upgrade pkg from 1.0.0 to one of: 1.0.5, 1.1.0.",
        dependency_scope="direct_runtime",
    )

    bal = decide([f], policy=PolicyConfig(profile="balanced"))
    assert bal.status == "WARN"

    strict = decide([f], policy=PolicyConfig(profile="strict"))
    assert strict.status == "FAIL"


def test_strict_does_not_fail_transitive_high_dep() -> None:
    """Even strict only blocks high-severity *direct* deps, not transitive."""
    f = _finding(
        source="grype", severity="high", title="CVE in transitive",
        recommendation="Upgrade pkg from 1.0.0 to one of: 1.0.5.",
        dependency_scope="transitive",
    )
    d = decide([f], policy=PolicyConfig(profile="strict"))
    assert d.status == "WARN"


def test_strict_does_not_change_pass_when_no_findings() -> None:
    d = decide([], policy=PolicyConfig(profile="strict"))
    assert d.status == "PASS"


# ----- balanced (default) is unchanged -----

def test_balanced_matches_default() -> None:
    """`PolicyConfig()` and `PolicyConfig(profile='balanced')` decide identically."""
    f = _finding(source="ai_discovery", severity="high", confidence=0.86, title="x")
    a = decide([f], policy=PolicyConfig())
    b = decide([f], policy=PolicyConfig(profile="balanced"))
    assert a.status == b.status == "WARN"


def test_default_profile_is_balanced() -> None:
    assert PolicyConfig().profile == "balanced"
