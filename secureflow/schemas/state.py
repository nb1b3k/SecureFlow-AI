"""The orchestrator state — the only thing that crosses node boundaries.

Parallel-written fields use reducers so LangGraph can merge writes from
the four scanner nodes that fan out from `collect_context`.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, TypedDict


def _merge_dict(a: dict, b: dict) -> dict:
    """Reducer for dicts where last-write-wins per key (e.g., scanner errors)."""
    return {**a, **b}


def _sum_dict(a: dict, b: dict) -> dict:
    """Reducer for numeric dicts where values accumulate (e.g., budget)."""
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return out


class SecurityReviewState(TypedDict, total=False):
    """The orchestrator's state object.

    Fields are deliberately `dict` rather than the typed Pydantic models so
    LangGraph's JSON-encodable state guarantees hold. Agents convert in/out
    via `Model.model_validate(...)` and `Model.model_dump()`.
    """

    # inputs
    config: dict
    repo_path: str
    pr_context: dict

    # parallel scanner outputs — need reducers
    secret_findings: Annotated[list[dict], add]
    sast_findings: Annotated[list[dict], add]
    dependency_findings: Annotated[list[dict], add]
    iac_findings: Annotated[list[dict], add]
    ai_discovery_findings: Annotated[list[dict], add]

    # single-writer fields
    normalized_findings: list[dict]
    mapped_findings: list[dict]
    reachability_hints: dict[str, str]
    exploitability_results: list[dict]
    patch_results: list[dict]
    final_findings: list[dict]

    # Threat Modeling Delta agent output — kept separate from
    # `final_findings` because design-level threats have a different
    # shape (no rule_id / start_line semantics) and a different
    # reporting section in the markdown report.
    threat_model_findings: list[dict]

    decision: dict
    markdown_report: str
    json_report_path: str
    sarif_report_path: str
    pr_comment_url: str | None

    # bookkeeping — need reducers
    budget_used: Annotated[dict[str, int], _sum_dict]
    scanner_errors: Annotated[dict[str, str], _merge_dict]
    prompt_versions: Annotated[dict[str, str], _merge_dict]
    node_timings: Annotated[dict[str, int], _merge_dict]
