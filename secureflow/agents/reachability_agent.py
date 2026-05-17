"""Path-based reachability hints.

v1 implements the cheap path classification only (under tests/ → unreachable,
under runtime dirs → likely_reachable, else unknown). The one-hop caller
lookup (design/06 §2.4) is a v2 enhancement.
"""

from __future__ import annotations

from secureflow.analysis.ast_signals import is_runtime_path
from secureflow.config import Config
from secureflow.utils.logging import get_logger

log = get_logger("agent.reachability")


def reachability_filter(state: dict) -> dict:
    cfg = Config.model_validate(state.get("config") or {})
    findings = list(state.get("mapped_findings") or [])

    hints: dict[str, str] = {}
    updated: list[dict] = []
    for f in findings:
        path = f.get("file_path") or ""
        hint: str
        if not path or not cfg.reachability.enabled:
            hint = "unknown"
        else:
            hint = is_runtime_path(
                path,
                excluded=cfg.reachability.excluded_runtime_dirs,
                runtime=cfg.reachability.runtime_dirs,
            )
        hints[f["id"]] = hint
        updated_f = dict(f)
        updated_f["reachability"] = hint
        updated.append(updated_f)

    log.info(
        "reachability classified %d findings (unreachable=%d likely=%d unknown=%d)",
        len(updated),
        sum(1 for h in hints.values() if h == "unreachable"),
        sum(1 for h in hints.values() if h == "likely_reachable"),
        sum(1 for h in hints.values() if h == "unknown"),
    )
    return {"reachability_hints": hints, "mapped_findings": updated}
