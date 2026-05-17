"""Semgrep runner + finding normalizer."""

from __future__ import annotations

from pathlib import Path

from secureflow.config import Config
from secureflow.schemas.finding import Severity
from secureflow.schemas.ids import compute_finding_id
from secureflow.tools.semgrep_runner import run_semgrep
from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import ToolNotFoundError

log = get_logger("agent.sast")


def _read_lines(repo_path: str, file_path: str | None, start: int | None, end: int | None) -> str:
    """Read lines [start, end] from `file_path` under `repo_path`. Used to
    populate finding evidence when semgrep returns the "requires login"
    placeholder for `extra.lines`. Best-effort: returns "" on any failure
    so the rest of the pipeline isn't blocked.
    """
    if not file_path or not start:
        return ""
    try:
        p = Path(file_path)
        if not p.is_absolute():
            p = Path(repo_path) / file_path
        if not p.exists() or not p.is_file():
            return ""
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        lo = max(0, int(start) - 1)
        hi = min(len(lines), int(end or start))
        return "\n".join(lines[lo:hi])[:2000]
    except (OSError, ValueError):
        return ""


def _to_str_list(val) -> list[str]:
    """Semgrep metadata fields are sometimes a single string, sometimes a list.

    Without this guard, `[v for v in "A01:..."]` would iterate characters
    and produce a malformed list.
    """
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [v for v in val if isinstance(v, str)]
    return []

# Semgrep's `severity` (ERROR / WARNING / INFO) reflects the rule author's
# confidence in matches, not the *bug's* impact. The actual security impact
# lives in `extra.metadata.impact` (HIGH / MEDIUM / LOW). We prefer that;
# fall back to the rule severity only when impact is absent.
_SEMGREP_SEV_MAP: dict[str, Severity] = {
    "INFO": "info",
    "WARNING": "medium",
    "ERROR": "high",
}
_IMPACT_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}
_LIKELIHOOD_TO_CONFIDENCE: dict[str, float] = {
    "HIGH": 0.90,
    "MEDIUM": 0.75,
    "LOW": 0.55,
}
_CONFIDENCE_META_TO_CONFIDENCE: dict[str, float] = {
    "HIGH": 0.90,
    "MEDIUM": 0.75,
    "LOW": 0.55,
}


def _severity(item: dict) -> Severity:
    """Map a Semgrep result to one of our `Severity` values.

    Order of precedence:
    1. `metadata.impact` — the rule author's stated bug impact.
    2. `extra.severity`  — fallback to rule-match severity (less accurate).
    """
    extra = item.get("extra", {}) or {}
    metadata = extra.get("metadata", {}) or {}
    impact = (metadata.get("impact") or "").upper()
    if impact in _IMPACT_MAP:
        return _IMPACT_MAP[impact]
    raw = (extra.get("severity") or "WARNING").upper()
    return _SEMGREP_SEV_MAP.get(raw, "medium")


def _confidence(item: dict) -> float:
    """Combine Semgrep's `likelihood` and `confidence` metadata into a 0-1 float.

    Falls back to a sensible default for rules that don't ship the metadata.
    """
    extra = item.get("extra", {}) or {}
    metadata = extra.get("metadata", {}) or {}
    likelihood = (metadata.get("likelihood") or "").upper()
    confidence = (metadata.get("confidence") or "").upper()
    if confidence in _CONFIDENCE_META_TO_CONFIDENCE:
        return _CONFIDENCE_META_TO_CONFIDENCE[confidence]
    if likelihood in _LIKELIHOOD_TO_CONFIDENCE:
        return _LIKELIHOOD_TO_CONFIDENCE[likelihood]
    return 0.75


def sast_scan(state: dict) -> dict:
    pr_context = state.get("pr_context") or {}
    repo_path = pr_context.get("repo_path") or "."
    cfg = Config.model_validate(state.get("config") or {})
    semgrep_config = cfg.scanners.semgrep.config or "auto"

    try:
        raw = run_semgrep(repo_path, config=semgrep_config)
    except ToolNotFoundError:
        log.info("semgrep not installed; skipping SAST scan")
        return {
            "sast_findings": [],
            "scanner_errors": {"semgrep": "not installed"},
        }
    except Exception as e:
        log.warning("semgrep failed: %s", e)
        return {
            "sast_findings": [],
            "scanner_errors": {"semgrep": f"{type(e).__name__}: {e}"[:300]},
        }

    findings: list[dict] = []
    for item in raw:
        rule_id = item.get("check_id") or "semgrep-rule"
        extra = item.get("extra", {}) or {}
        message = extra.get("message") or rule_id
        file_path = item.get("path")
        start = (item.get("start") or {})
        end = (item.get("end") or {})
        start_line = start.get("line")
        end_line = end.get("line")
        snippet = (extra.get("lines") or "")[:2000]
        # Semgrep returns the placeholder "requires login" for `extra.lines`
        # on most rules when the runner isn't authenticated to the Semgrep
        # registry (which is the default in CI). The PR comment then shows
        # "requires login" instead of the actual matched code — confusing
        # and useless. Read the actual lines ourselves as a fallback.
        if snippet.strip() == "requires login":
            snippet = _read_lines(repo_path, file_path, start_line, end_line)

        metadata = extra.get("metadata", {}) or {}
        cwe = _to_str_list(metadata.get("cwe"))
        owasp = _to_str_list(metadata.get("owasp"))

        finding_id = compute_finding_id(
            source="semgrep",
            title=message,
            file_path=file_path,
            rule_id=rule_id,
            symbol=None,
            start_line=start_line,
            end_line=end_line,
            code=snippet,
        )

        findings.append({
            "id": finding_id,
            "source": "semgrep",
            "rule_id": rule_id,
            "title": message[:200],
            "description": message,
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "symbol": None,
            "severity": _severity(item),
            "confidence": _confidence(item),
            "evidence": snippet,
            "cwe": cwe,
            "owasp": owasp,
            "mitre_attack": [],
            "cve": [],
            "reachability": "unknown",
            "exploitability": None,
            "attacker_scenario": None,
            "impact": None,
            "false_positive": False,
            "false_positive_reason": None,
            "recommendation": extra.get("fix") or None,
            "patch_unified_diff": None,
            "patch_explanation": None,
            "patch_status": "none",
            "patch_verification_notes": None,
            "prompt_version": None,
        })

    log.info("sast scan complete: %d findings", len(findings))
    return {"sast_findings": findings}
