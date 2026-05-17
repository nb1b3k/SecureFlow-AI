"""LangGraph state machine for SecureFlow AI.

See `design/02_orchestrator.md` for the full topology, contracts, and
error semantics. This file is the wiring.
"""

from __future__ import annotations

from typing import Any

from secureflow.agents import (
    ai_discovery,
    collect_context,
    decision_node,
    dependency_scan,
    enrich_findings,
    exploitability,
    iac_scan,
    normalize,
    patch_generation,
    reachability_filter,
    sast_scan,
    secrets_scan,
    threat_map,
    threat_model_delta,
)
from secureflow.config import Config
from secureflow.orchestrator.conditions import route_after_context
from secureflow.orchestrator.errors import OrchestratorError
from secureflow.schemas.state import SecurityReviewState
from secureflow.utils.logging import get_logger
from secureflow.utils.timing import timed_node

log = get_logger("orchestrator")


def build_graph():
    """Compile the LangGraph state graph.

    Lazy-imported so the package imports even when `langgraph` is missing.
    """
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as e:
        raise OrchestratorError(
            "langgraph is not installed. Run `py -m pip install langgraph`."
        ) from e

    g = StateGraph(SecurityReviewState)

    # Every node is wrapped so each step's entry/exit/duration shows up in
    # logs and JSON telemetry. Makes "where is the pipeline stuck?" answerable.
    g.add_node("collect_context", timed_node("collect_context")(collect_context))
    g.add_node("secrets_scan", timed_node("secrets_scan")(secrets_scan))
    g.add_node("sast_scan", timed_node("sast_scan")(sast_scan))
    g.add_node("dependency_scan", timed_node("dependency_scan")(dependency_scan))
    g.add_node("iac_scan", timed_node("iac_scan")(iac_scan))
    g.add_node("ai_discovery", timed_node("ai_discovery")(ai_discovery))
    g.add_node("normalize", timed_node("normalize")(normalize))
    g.add_node("threat_map", timed_node("threat_map")(threat_map))
    g.add_node("enrich_findings", timed_node("enrich_findings")(enrich_findings))
    g.add_node("reachability_filter", timed_node("reachability_filter")(reachability_filter))
    g.add_node("exploitability", timed_node("exploitability")(exploitability))
    g.add_node("patch_generation", timed_node("patch_generation")(patch_generation))
    g.add_node("threat_model", timed_node("threat_model")(threat_model_delta))
    g.add_node("decide", timed_node("decide")(decision_node))

    g.add_edge(START, "collect_context")
    g.add_conditional_edges(
        "collect_context",
        route_after_context,
        {
            "decide": "decide",
            "secrets_scan": "secrets_scan",
            "sast_scan": "sast_scan",
            "dependency_scan": "dependency_scan",
            "iac_scan": "iac_scan",
            "ai_discovery": "ai_discovery",
        },
    )

    # All scanners (and AI Discovery) converge on normalize.
    for src in ("secrets_scan", "sast_scan", "dependency_scan", "iac_scan", "ai_discovery"):
        g.add_edge(src, "normalize")

    g.add_edge("normalize", "threat_map")
    g.add_edge("threat_map", "enrich_findings")
    g.add_edge("enrich_findings", "reachability_filter")
    g.add_edge("reachability_filter", "exploitability")
    g.add_edge("exploitability", "patch_generation")
    # Threat modeling runs in parallel with patch_generation: both have
    # the same upstream (`exploitability`) and neither reads the other's
    # output. LangGraph fans out automatically since both edges leave
    # `exploitability`, and the schema reducers merge their state writes
    # cleanly (different fields).
    g.add_edge("exploitability", "threat_model")
    g.add_edge("patch_generation", "decide")
    g.add_edge("threat_model", "decide")
    g.add_edge("decide", END)

    return g.compile()


def run_pipeline(
    *,
    cfg: Config,
    repo_path: str,
) -> dict[str, Any]:
    """Build and run the graph end-to-end. Returns the final state dict.

    Reporting and PR-commenting are handled outside the graph (by the CLI)
    so the graph itself can be reused from other contexts (eval harness).
    """
    initial_state: dict[str, Any] = {
        "config": cfg.model_dump(),
        "repo_path": repo_path,
        "secret_findings": [],
        "sast_findings": [],
        "dependency_findings": [],
        "iac_findings": [],
        "ai_discovery_findings": [],
        "threat_model_findings": [],
        "scanner_errors": {},
        "budget_used": {},
        "prompt_versions": {},
    }
    graph = build_graph()
    log.info("starting orchestrator", extra={"repo": repo_path})
    final_state = graph.invoke(initial_state)
    log.info(
        "orchestrator finished",
        extra={
            "decision": (final_state.get("decision") or {}).get("status"),
            "findings": len(final_state.get("final_findings") or []),
            "scanner_errors": list((final_state.get("scanner_errors") or {}).keys()),
        },
    )
    return final_state
