"""The policy engine.

Inputs: a list of `Finding` (dicts) and the user's `PolicyConfig`.
Output: a `Decision`.

Rules implemented:
- FAIL on critical secrets, critical CVEs, confirmed high-confidence injection,
  AI-discovered critical issues with confidence >= 0.85.
- WARN on medium-confidence AI findings, outdated dependencies without
  confirmed exploitability.
- PASS otherwise.

The engine also computes a transparent 0-100 risk score (plan §18) and
attaches reasons / required-actions for the report.
"""

from __future__ import annotations

from collections.abc import Iterable

from secureflow.config import PolicyConfig
from secureflow.schemas.decision import Decision

_SEVERITY_BASE = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 1,
}

_HIGH_IMPACT_RULE_KEYWORDS = (
    # SQL injection — semgrep emits multiple rule families
    "sqli", "sql-injection", "sql_injection", "sql-string", "tainted-sql",
    "sqlalchemy-execute-raw",
    "string-formatted-query", "formatted-sql-string",  # Go / Java / C#
    # Command / code injection
    "command-injection", "shell-injection", "subprocess-injection",
    "dangerous-subprocess", "code-injection",
    "rce", "remote-code-execution",
    "dangerous-subshell",        # Ruby `..` / system(..) with interpolation
    "dangerous-spawn-shell", "dangerous-exec", "detect-child-process",  # JS / TS
    # SSRF
    "ssrf", "server-side-request-forgery",
    # Deserialization
    "deserialization", "pickle", "unsafe-yaml", "yaml-load",
    # XML / XXE
    "xxe", "lxml-with-xxe", "lxml-in-etree",
    "documentbuilderfactory-disallow-doctype",     # Java XXE rule
    "documentbuilderfactory-disable-external",     # Java XXE rule
    "external-entity",
    # Auth / sessions
    "auth-bypass", "jwt-decode-without-verify", "verify_signature",
    # Path traversal — semgrep emits per-language but a common substring works
    "path-traversal", "directory-traversal",
    # Generic injection — catches anything that semgrep names "injection.*"
    "injection.",
)


def _is_high_impact(rule_id: str | None, title: str) -> bool:
    text = f"{rule_id or ''}|{title}".lower()
    return any(k in text for k in _HIGH_IMPACT_RULE_KEYWORDS)


def _score_one(finding: dict) -> int:
    base = _SEVERITY_BASE.get(finding.get("severity", "info"), 1)
    score = base
    confidence = float(finding.get("confidence") or 0.0)
    if confidence >= 0.90:
        score += 10
    if finding.get("source") in {"gitleaks"} and finding.get("severity") == "critical":
        score += 20  # exposed secret bonus
    if finding.get("false_positive"):
        score = max(0, score - 20)
    if finding.get("patch_status") in {"verified", "suggested"}:
        score = max(0, score - 5)
    if finding.get("reachability") == "unreachable":
        score = max(0, score - 10)
    return score


def _aggregate_risk(findings: Iterable[dict]) -> int:
    total = sum(_score_one(f) for f in findings if not f.get("false_positive"))
    return min(100, total)


def decide(
    findings: list[dict],
    *,
    policy: PolicyConfig,
    skipped_components: list[str] | None = None,
    threat_model_findings: list[dict] | None = None,
) -> Decision:
    """Produce the final Decision.

    `threat_model_findings` (optional) carries the design-level threats
    from the threat-modeling delta agent. We let them WARN but only let
    them FAIL when both severity is critical/high AND confidence is
    above the configured fail threshold — same posture as AI-only
    findings, since both are LLM-derived.
    """
    reasons: list[str] = []
    required: list[str] = []
    contributing_ids: list[str] = []
    status: str = "PASS"

    fail = False
    warn = False

    for f in findings:
        if f.get("false_positive"):
            continue

        sev = f.get("severity", "info")
        conf = float(f.get("confidence") or 0.0)
        source = f.get("source")
        title = f.get("title") or ""
        rule_id = f.get("rule_id")
        fid = f.get("id")

        # Critical hardcoded secret → FAIL.
        if source == "gitleaks" and sev == "critical":
            fail = True
            reasons.append(f"Critical secret: {title}")
            required.append("Remove the secret and rotate the exposed credential.")
            if fid:
                contributing_ids.append(fid)
            continue

        # Critical CVE in deps → FAIL.
        if source in {"grype", "osv"} and sev == "critical":
            fail = True
            reasons.append(f"Critical CVE: {title}")
            required.append("Upgrade affected dependency to a fixed version.")
            if fid:
                contributing_ids.append(fid)
            continue

        # SAST findings on canonical high-impact patterns → FAIL.
        #
        # The pattern keywords in _HIGH_IMPACT_RULE_KEYWORDS represent bug
        # classes that are FAIL-worthy by industry consensus: pickle.loads
        # on attacker bytes, raw SQL string concatenation, shell=True with
        # interpolation, etc. Semgrep's `severity` and `confidence` reflect
        # its uncertainty about whether *this match* is a true positive,
        # not whether the bug class is dangerous. We treat any reasonable
        # confidence (>=0.50) on a known-bad pattern as FAIL. The LLM
        # exploitability layer is the right tool for downgrading genuine
        # false positives — over-conservative scanner severity is not.
        if source in {"semgrep", "bandit"} and sev != "info":
            high_impact = _is_high_impact(rule_id, title)
            if high_impact and conf >= 0.50:
                fail = True
                reasons.append(f"High-impact SAST pattern: {title}")
                required.append("Apply a parameterized / sanitized / authorized pattern.")
                if fid:
                    contributing_ids.append(fid)
                continue

        # AI-discovered critical + high confidence → FAIL; otherwise WARN.
        if source == "ai_discovery":
            if sev == "critical" and conf >= 0.85:
                fail = True
                reasons.append(f"AI-discovered critical risk: {title}")
                required.append("Investigate and remediate AI-identified vulnerability.")
                if fid:
                    contributing_ids.append(fid)
            elif sev in {"medium", "high"} and conf >= policy.minimum_warn_confidence:
                warn = True
                reasons.append(f"AI-discovered risk needs review: {title}")
                if fid:
                    contributing_ids.append(fid)
            continue

        # Dependency CVE medium/high without confirmed exploitability → WARN.
        if source in {"grype", "osv"} and sev in {"medium", "high"}:
            warn = True
            reasons.append(f"Outdated/vulnerable dependency: {title}")
            if fid:
                contributing_ids.append(fid)
            continue

        # Any remaining medium+/high-severity finding → WARN as a default
        # conservative posture. Medium covers weak-crypto, ssl-verify-False,
        # open-redirect, and similar "not great but not RCE" issues that
        # security engineers want flagged for review even if they don't
        # block the merge.
        if sev in {"medium", "high", "critical"} and conf >= policy.minimum_warn_confidence:
            warn = True
            reasons.append(f"Finding requires review: {title}")
            if fid:
                contributing_ids.append(fid)

    # Threat-modeling delta — design-level threats. Same posture as AI
    # discovery: only FAIL on high-confidence high-severity threats with
    # a `FAIL` suggested_decision; otherwise WARN. Reasoning: a threat
    # model is a soft signal — useful for review, not for blocking on
    # its own unless it's very high-confidence (e.g. "new admin route
    # with zero auth middleware in the diff").
    for t in (threat_model_findings or []):
        sev = t.get("severity", "medium")
        conf = float(t.get("confidence") or 0.0)
        suggested = t.get("suggested_decision", "WARN")
        title = t.get("title") or "design change"
        change = t.get("change_type") or "design change"
        if (
            suggested == "FAIL"
            and sev in {"critical", "high"}
            and conf >= policy.minimum_fail_confidence
        ):
            fail = True
            reasons.append(f"Threat model FAIL: {title} ({change})")
            required.extend(t.get("mitigations") or [])
        elif (
            sev in {"medium", "high", "critical"}
            and conf >= policy.minimum_warn_confidence
        ):
            warn = True
            reasons.append(f"Threat model needs review: {title} ({change})")

    if fail:
        status = "FAIL"
    elif warn:
        status = "WARN"

    score = _aggregate_risk(findings)
    summary = _summary(status, score, len(reasons))

    return Decision(
        status=status,  # type: ignore[arg-type]
        risk_score=score,
        summary=summary,
        reasons=reasons,
        required_actions=required,
        finding_ids=contributing_ids,
        skipped_components=list(skipped_components or []),
    )


def _summary(status: str, score: int, n: int) -> str:
    if status == "PASS":
        return f"No blocking findings. Risk score {score}/100."
    if status == "WARN":
        return f"{n} finding(s) need human review. Risk score {score}/100."
    return f"{n} blocking finding(s). Risk score {score}/100. PR should not merge."
