"""Conditional-edge predicates for the orchestrator graph."""

from __future__ import annotations

from collections.abc import Iterable


def has_relevant_changes(state: dict) -> bool:
    """True if there are changed files to analyze."""
    pr = state.get("pr_context") or {}
    return bool(pr.get("changed_files"))


def route_after_context(state: dict) -> list[str] | str:
    """Fan out to the scanner layer, or skip to decision if no changes."""
    if not has_relevant_changes(state):
        return "decide"
    return ["secrets_scan", "sast_scan", "dependency_scan", "iac_scan", "ai_discovery"]


def has_findings_to_patch(state: dict) -> bool:
    """True if there is at least one non-FP finding to consider for patching."""
    return any(
        not f.get("false_positive")
        for f in (state.get("exploitability_results") or [])
    )


def has_open_findings(findings: Iterable[dict]) -> bool:
    return any(not f.get("false_positive") for f in findings)
