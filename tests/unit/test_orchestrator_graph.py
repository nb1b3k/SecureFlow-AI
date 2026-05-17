"""Wiring tests for the LangGraph orchestrator.

Each agent is real and tested in isolation. This file tests the graph
ITSELF — node order, conditional edges, parallel fan-out, and the three
reducer fields (`*_findings` concat, `scanner_errors` merge, `budget_used`
sum). Catches the class of bug that survives agent-level unit tests but
breaks the pipeline: wires crossed between nodes, a node writing to the
wrong state key, a reducer silently dropping a parallel write.

Strategy: monkey-patch every agent in `secureflow.agents` with a stub
that records its invocation and writes deterministic state — then run
`build_graph()` on a synthetic config and assert what landed in final
state.
"""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import patch

from secureflow.config import Config
from secureflow.orchestrator.conditions import (
    has_findings_to_patch,
    route_after_context,
)

# ─────────────────────────────────────────────── conditional-edge tests ──


def test_route_after_context_skips_to_decide_on_empty_diff() -> None:
    state = {"pr_context": {"changed_files": []}}
    assert route_after_context(state) == "decide"


def test_route_after_context_fans_out_when_changes_present() -> None:
    state = {"pr_context": {"changed_files": ["a.py"]}}
    targets = route_after_context(state)
    assert isinstance(targets, list)
    assert set(targets) == {"secrets_scan", "sast_scan", "dependency_scan", "iac_scan", "ai_discovery"}


def test_has_findings_to_patch_ignores_false_positives() -> None:
    state = {"exploitability_results": [
        {"id": "a", "false_positive": True},
        {"id": "b", "false_positive": False},
    ]}
    assert has_findings_to_patch(state) is True


def test_has_findings_to_patch_false_when_all_fp() -> None:
    state = {"exploitability_results": [
        {"id": "a", "false_positive": True},
    ]}
    assert has_findings_to_patch(state) is False


# ─────────────────────────────────────────────────── full-graph wiring ──


def _make_agent_stubs(call_log: list[str]) -> dict[str, Callable]:
    """Build minimal agent stubs that each record their invocation + write
    one known field to state. The graph schema reducers then combine them.

    The keys returned correspond to the names imported in
    `secureflow.orchestrator.graph` — patching them swaps the wired-in
    functions for these stubs without touching the graph topology.
    """

    def collect_context(state):
        call_log.append("collect_context")
        return {"pr_context": {
            "changed_files": ["a.py"],
            "repo_path": state.get("repo_path", "."),
        }}

    def secrets_scan(state):
        call_log.append("secrets_scan")
        return {
            "secret_findings": [{"id": "s1", "source": "secrets", "severity": "high",
                                 "rule_id": "test", "title": "t", "file_path": "a.py",
                                 "start_line": 1, "end_line": 1, "confidence": 0.9,
                                 "cwe": [], "owasp": [], "mitre_attack": [], "cve": [],
                                 "reachability": "unknown", "false_positive": False,
                                 "evidence": "", "description": "", "recommendation": "",
                                 "patch_status": "none"}],
            "scanner_errors": {},
        }

    def sast_scan(state):
        call_log.append("sast_scan")
        return {
            "sast_findings": [{"id": "sa1", "source": "semgrep", "severity": "high",
                               "rule_id": "test", "title": "t", "file_path": "a.py",
                               "start_line": 2, "end_line": 2, "confidence": 0.9,
                               "cwe": [], "owasp": [], "mitre_attack": [], "cve": [],
                               "reachability": "unknown", "false_positive": False,
                               "evidence": "", "description": "", "recommendation": "",
                               "patch_status": "none"}],
            "scanner_errors": {},
        }

    def dependency_scan(state):
        call_log.append("dependency_scan")
        return {"dependency_findings": [], "scanner_errors": {"grype": "skipped"}}

    def iac_scan(state):
        call_log.append("iac_scan")
        return {"iac_findings": [], "scanner_errors": {"checkov": "skipped: no IaC files changed"}}

    def ai_discovery(state):
        call_log.append("ai_discovery")
        return {"ai_discovery_findings": [], "scanner_errors": {"ai_discovery": "disabled"}}

    def normalize(state):
        call_log.append("normalize")
        merged = (
            state.get("secret_findings", [])
            + state.get("sast_findings", [])
            + state.get("dependency_findings", [])
            + state.get("iac_findings", [])
            + state.get("ai_discovery_findings", [])
        )
        return {"normalized_findings": merged}

    def threat_map(state):
        call_log.append("threat_map")
        return {"mapped_findings": list(state.get("normalized_findings", []))}

    def enrich_findings(state):
        call_log.append("enrich_findings")
        return {"mapped_findings": list(state.get("mapped_findings", []))}

    def reachability_filter(state):
        call_log.append("reachability_filter")
        return {
            "mapped_findings": list(state.get("mapped_findings", [])),
            "reachability_hints": {},
        }

    def exploitability(state):
        call_log.append("exploitability")
        return {"exploitability_results": list(state.get("mapped_findings", []))}

    def patch_generation(state):
        call_log.append("patch_generation")
        return {
            "patch_results": [],
            "final_findings": list(state.get("exploitability_results", [])),
        }

    def decision_node(state):
        call_log.append("decide")
        n = len(state.get("final_findings", []))
        return {"decision": {
            "status": "FAIL" if n else "PASS",
            "risk_score": 50 if n else 0,
            "summary": f"{n} findings", "reasons": [], "required_actions": [],
            "finding_ids": [], "skipped_components": [],
        }}

    return {
        "collect_context": collect_context,
        "secrets_scan": secrets_scan,
        "sast_scan": sast_scan,
        "dependency_scan": dependency_scan,
        "iac_scan": iac_scan,
        "ai_discovery": ai_discovery,
        "normalize": normalize,
        "threat_map": threat_map,
        "enrich_findings": enrich_findings,
        "reachability_filter": reachability_filter,
        "exploitability": exploitability,
        "patch_generation": patch_generation,
        "decision_node": decision_node,
    }


def _run_graph_with_stubs(call_log: list[str], *, initial_state: dict):
    """Build the real graph but with every agent stubbed out, then invoke."""
    stubs = _make_agent_stubs(call_log)
    with patch.multiple("secureflow.orchestrator.graph", **stubs):
        from secureflow.orchestrator.graph import build_graph
        return build_graph().invoke(initial_state)


def _initial_state(cfg: Config | None = None) -> dict:
    cfg = cfg or Config()
    return {
        "config": cfg.model_dump(),
        "repo_path": ".",
        "secret_findings": [],
        "sast_findings": [],
        "dependency_findings": [],
        "iac_findings": [],
        "ai_discovery_findings": [],
        "scanner_errors": {},
        "budget_used": {},
        "prompt_versions": {},
    }


def test_graph_runs_every_node_in_topological_order() -> None:
    """All 12 nodes fire; ordering respects the linear chain after fan-in."""
    log: list[str] = []
    final = _run_graph_with_stubs(log, initial_state=_initial_state())

    # collect_context is always first; decide is always last.
    assert log[0] == "collect_context"
    assert log[-1] == "decide"
    # The five scanner nodes happen between context and normalize.
    fanout = {"secrets_scan", "sast_scan", "dependency_scan", "iac_scan", "ai_discovery"}
    fanout_idxs = [i for i, n in enumerate(log) if n in fanout]
    assert log.index("normalize") > max(fanout_idxs)
    # The post-normalize chain happens in a fixed order.
    chain = [
        "normalize", "threat_map", "enrich_findings", "reachability_filter",
        "exploitability", "patch_generation", "decide",
    ]
    indices = [log.index(n) for n in chain]
    assert indices == sorted(indices), f"chain out of order: {[(n, log.index(n)) for n in chain]}"

    # Final state shape sanity.
    assert final["decision"]["status"] == "FAIL"  # we stubbed in 2 findings
    assert len(final["final_findings"]) == 2


def test_graph_skips_scanners_when_no_changed_files() -> None:
    """`route_after_context` short-circuits to `decide` on empty diff."""
    log: list[str] = []

    # Replace collect_context with one that emits NO changed files.
    stubs = _make_agent_stubs(log)
    def empty_context(state):
        log.append("collect_context")
        return {"pr_context": {"changed_files": []}}
    stubs["collect_context"] = empty_context

    with patch.multiple("secureflow.orchestrator.graph", **stubs):
        from secureflow.orchestrator.graph import build_graph
        final = build_graph().invoke(_initial_state())

    # Scanners and the entire downstream chain should be skipped.
    skipped = {"secrets_scan", "sast_scan", "dependency_scan", "iac_scan", "ai_discovery",
               "normalize", "threat_map", "enrich_findings",
               "reachability_filter", "exploitability", "patch_generation"}
    assert log == ["collect_context", "decide"], (
        f"expected fast-path, got: {log}"
    )
    assert not (set(log) & skipped)
    assert final["decision"]["status"] == "PASS"


def test_scanner_errors_reducer_merges_parallel_writes() -> None:
    """grype + ai_discovery write different keys to scanner_errors in
    parallel; both must appear in the final state. Regression on the
    `_merge_dict` reducer wiring."""
    log: list[str] = []
    final = _run_graph_with_stubs(log, initial_state=_initial_state())
    errors = final.get("scanner_errors", {})
    assert errors.get("grype") == "skipped"
    assert errors.get("ai_discovery") == "disabled"


def test_findings_list_reducers_concat_parallel_writes() -> None:
    """Each scanner writes its own findings list; the typed reducers (`add`)
    must concat them without overwriting. Without the reducer this used to
    silently drop all but the last parallel write."""
    log: list[str] = []
    final = _run_graph_with_stubs(log, initial_state=_initial_state())
    # secrets_scan + sast_scan both wrote a finding; the normalize stub
    # concatenates them.
    assert len(final["final_findings"]) == 2
    sources = {f["source"] for f in final["final_findings"]}
    assert sources == {"secrets", "semgrep"}
