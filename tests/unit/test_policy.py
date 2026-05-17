"""Unit tests for the deterministic policy engine."""

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


def test_no_findings_is_pass() -> None:
    d = decide([], policy=PolicyConfig())
    assert d.status == "PASS"
    assert d.risk_score == 0


def test_critical_secret_fails() -> None:
    f = _finding(source="gitleaks", severity="critical", title="AWS key")
    d = decide([f], policy=PolicyConfig())
    assert d.status == "FAIL"
    assert "critical" in d.summary.lower() or "blocking" in d.summary.lower()


def test_high_confidence_sqli_fails() -> None:
    f = _finding(
        source="semgrep", severity="high", confidence=0.9,
        rule_id="python.lang.security.sqli", title="SQL injection",
    )
    d = decide([f], policy=PolicyConfig())
    assert d.status == "FAIL"


def test_low_confidence_high_finding_is_warn() -> None:
    f = _finding(source="semgrep", severity="high", confidence=0.6, rule_id="generic")
    d = decide([f], policy=PolicyConfig())
    assert d.status == "WARN"


def test_ai_only_medium_is_warn() -> None:
    f = _finding(source="ai_discovery", severity="medium", confidence=0.7, title="logic flaw")
    d = decide([f], policy=PolicyConfig())
    assert d.status == "WARN"


def test_ai_only_critical_high_conf_fails() -> None:
    f = _finding(source="ai_discovery", severity="critical", confidence=0.9, title="auth bypass")
    d = decide([f], policy=PolicyConfig())
    assert d.status == "FAIL"


def test_false_positive_is_ignored() -> None:
    f = _finding(
        source="gitleaks", severity="critical", title="AWS key",
        false_positive=True,
    )
    d = decide([f], policy=PolicyConfig())
    assert d.status == "PASS"


def test_unreachable_finding_lowers_score() -> None:
    f = _finding(source="semgrep", severity="high", reachability="unreachable")
    d = decide([f], policy=PolicyConfig())
    # Score is reduced by 10 vs reachable
    assert d.risk_score < 25
