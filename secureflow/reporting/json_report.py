"""Structured JSON report — the machine-readable artifact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secureflow import __version__


def build_json_report(state: dict) -> dict[str, Any]:
    """Distill the final state into a stable JSON shape."""
    return {
        "secureflow_version": __version__,
        "decision": state.get("decision") or {},
        "findings": state.get("final_findings") or state.get("mapped_findings") or [],
        # Threat-model findings live in a separate state field because they
        # have a different schema (ThreatModelItem) from the regular
        # `Finding` objects. The markdown report has rendered them since
        # the agent shipped; the JSON report missed them, so SARIF
        # transformers and custom dashboards couldn't see design-level
        # threats even though the markdown bot comment did.
        "threat_model_findings": state.get("threat_model_findings") or [],
        "pr_context": state.get("pr_context") or {},
        "scanner_errors": state.get("scanner_errors") or {},
        "budget_used": state.get("budget_used") or {},
        "prompt_versions": state.get("prompt_versions") or {},
    }


def write_json_report(state: dict, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(build_json_report(state), f, ensure_ascii=False, indent=2)
    return p
