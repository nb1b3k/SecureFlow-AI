"""Re-scan dispatcher for patch validation.

Given a finding and a worktree path, re-run the scanner that originally
produced the finding and report whether the same issue is still present.

Matching is intentionally fuzzy: a patch can shift line numbers, rename
variables, and even change the exact rule fingerprint while still failing
to address the underlying issue. We treat any finding in the same
(file, rule_id, line ± 5) as the original still being present.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from secureflow.tools.gitleaks_runner import run_gitleaks
from secureflow.tools.grype_runner import run_grype
from secureflow.tools.semgrep_runner import run_semgrep
from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import ToolNotFoundError

log = get_logger("rescan")


@dataclass
class RescanResult:
    finding_still_present: bool
    error: str | None = None  # set when the scanner couldn't run


def rerun_for(finding: dict, *, worktree_root: str, semgrep_config: str = "auto") -> RescanResult:
    """Dispatch to the right scanner for `finding` and check if it persists."""
    source = finding.get("source")
    try:
        if source == "gitleaks":
            findings = run_gitleaks(worktree_root)
        elif source in {"semgrep", "bandit"}:
            findings = run_semgrep(worktree_root, config=semgrep_config)
        elif source in {"grype", "osv"}:
            findings = run_grype(worktree_root)
        else:
            # ai_discovery findings have no scanner to re-run against. The
            # caller should not get here, but defend in depth.
            return RescanResult(finding_still_present=False, error="not_applicable")
    except ToolNotFoundError as e:
        return RescanResult(finding_still_present=False, error=f"tool_missing:{e}")
    except Exception as e:
        return RescanResult(finding_still_present=False, error=f"{type(e).__name__}:{e}"[:200])

    still = _still_present(finding, findings, source)
    log.debug(
        "rescan",
        extra={
            "finding_id": finding.get("id"),
            "scanner": source,
            "rescan_count": len(findings),
            "still_present": still,
        },
    )
    return RescanResult(finding_still_present=still)


# ─────────────────────────────────────────────────────────── matchers ──


def _still_present(original: dict, current: Iterable[dict], source: str) -> bool:
    """Heuristically determine if the original finding is still flagged."""
    if source == "gitleaks":
        return _gitleaks_still_present(original, current)
    if source in {"semgrep", "bandit"}:
        return _semgrep_still_present(original, current)
    if source in {"grype", "osv"}:
        return _grype_still_present(original, current)
    return False


def _gitleaks_still_present(original: dict, current: Iterable[dict]) -> bool:
    """A gitleaks finding is still present if any new finding has the same
    rule on the same file within ±5 lines of the original."""
    rule = (original.get("rule_id") or "").lower()
    file_norm = _norm_path(original.get("file_path"))
    line = original.get("start_line") or 0
    for item in current:
        rid = (item.get("RuleID") or item.get("Rule") or "").lower()
        if rid != rule:
            continue
        if _norm_path(item.get("File")) != file_norm:
            continue
        item_line = item.get("StartLine") or item.get("Line") or 0
        if abs(item_line - line) <= 5:
            return True
    return False


def _semgrep_still_present(original: dict, current: Iterable[dict]) -> bool:
    """A semgrep finding is still present if any new finding shares rule_id
    and file path within ±5 lines of the original."""
    rule = (original.get("rule_id") or "").lower()
    file_norm = _norm_path(original.get("file_path"))
    line = original.get("start_line") or 0
    for item in current:
        rid = (item.get("check_id") or "").lower()
        if rid != rule:
            continue
        if _norm_path(item.get("path")) != file_norm:
            continue
        item_line = ((item.get("start") or {}).get("line")) or 0
        if abs(item_line - line) <= 5:
            return True
    return False


def _grype_still_present(original: dict, current: Iterable[dict]) -> bool:
    """A grype finding is still present if any new finding has the same CVE
    on the same package@version."""
    rule = (original.get("rule_id") or "").upper()
    symbol = (original.get("symbol") or "").lower()  # e.g. "django@2.2.0"
    for item in current:
        vuln = item.get("vulnerability", {}) or {}
        artifact = item.get("artifact", {}) or {}
        if (vuln.get("id") or "").upper() != rule:
            continue
        sym = f"{artifact.get('name','?').lower()}@{artifact.get('version','?').lower()}"
        if sym == symbol:
            return True
    return False


def _norm_path(p: str | None) -> str:
    if not p:
        return ""
    return p.replace("\\", "/").lstrip("./").lower()
