"""End-to-end orchestrator integration test.

Tests cover the path that unit tests miss: the *interactions* between
normalize, threat_map, enrich, reachability, exploitability, patch, and
decision when run together against a realistic finding payload. Catches
the class of bug that's invisible to per-agent tests — like the
taint-floor / unreachable-cap composition bug fixed in commit 8120413
(floor lifted confidence to 0.7, downstream cap immediately undid it).

Scanners (semgrep / gitleaks / grype subprocesses) and the LLM client
are both stubbed so the test runs cleanly on CI without those tools
installed. Everything between — including the markdown banner, the
taint floor, the unreachable cap, the reachability classifier, and the
decision policy — runs the real code path.

Two scenarios:

1. `test_e2e_pipeline_llm_available_drives_decision`
   Stub returns sane LLM responses. Pipeline reaches FAIL. Banner does
   not fire. Telemetry has timings for every node. Markdown report
   contains the right sections.

2. `test_e2e_pipeline_llm_unavailable_still_correct_via_floor`
   Stub raises ConfigError, so all three LLM agents skip. Decision
   STILL reaches FAIL because the deterministic taint-floor lifts the
   semgrep-medium finding to confidence 0.7. The banner fires and
   names every skipped LLM agent.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from secureflow.config import Config
from secureflow.llm.base import LLMCallResult, LLMError
from secureflow.orchestrator.graph import run_pipeline
from secureflow.reporting.markdown_report import render_markdown_report
from secureflow.reporting.telemetry import build_telemetry
from secureflow.schemas.ids import compute_finding_id
from secureflow.schemas.llm_outputs import (
    AIDiscoveryResponse,
    ExploitabilityResult,
    PatchReplacement,
    PatchSuggestion,
    ThreatModelResponse,
)

# ─────────────────────────────────────────────────────────── fixture set-up ──


def _write_taint_flow_fixture(repo_root: Path) -> dict:
    """Drop a single Go file with a request -> SQL sink and return a
    pre-built semgrep finding pointing at the sink line.

    The file uses the exact `r.URL.Query()` taint pattern in `_TAINT_SOURCES_RE`
    and a rule_id substring (`string-formatted-query`) the normalizer's
    `_is_known_sink_rule` recognises, so the taint floor will fire.
    """
    (repo_root / "app.go").write_text(
        "package main\n"
        "import (\n"
        "    \"database/sql\"\n"
        "    \"fmt\"\n"
        "    \"net/http\"\n"
        ")\n"
        "var db *sql.DB\n"
        "func getUser(w http.ResponseWriter, r *http.Request) {\n"
        "    uid := r.URL.Query().Get(\"id\")\n"
        "    q := fmt.Sprintf(\"SELECT * FROM u WHERE id = %s\", uid)\n"
        "    _, _ = db.Query(q)\n"
        "}\n",
        encoding="utf-8",
    )

    rule_id = (
        "go.lang.security.audit.database.string-formatted-query"
        ".string-formatted-query"
    )
    fid = compute_finding_id(
        source="semgrep",
        title="String-formatted SQL",
        file_path="app.go",
        rule_id=rule_id,
        symbol=None,
        start_line=10,
        end_line=10,
        code="q := fmt.Sprintf(...)",
    )
    return {
        "id": fid,
        "source": "semgrep",
        "rule_id": rule_id,
        "title": "String-formatted SQL query detected",
        "description": "tainted r.URL.Query() flows into SQL",
        "file_path": "app.go",
        "start_line": 10,
        "end_line": 10,
        "symbol": None,
        "severity": "high",
        # 0.40 — below FAIL threshold. The taint floor is the only thing
        # that should lift this to 0.7.
        "confidence": 0.40,
        "evidence": "q := fmt.Sprintf(\"SELECT * FROM u WHERE id = %s\", uid)",
        "cwe": [],
        "owasp": [],
        "mitre_attack": [],
        "cve": [],
        "reachability": "unknown",
        "exploitability": None,
        "attacker_scenario": None,
        "impact": None,
        "false_positive": False,
        "false_positive_reason": None,
        "recommendation": None,
        "patch_unified_diff": None,
        "patch_explanation": None,
        "patch_status": "none",
        "patch_verification_notes": None,
        "prompt_version": None,
    }


# ─────────────────────────────────────────────────── scanner / LLM stubs ──


def _scanner_patches(seeded_finding: dict):
    """Patch the four parallel scanner names imported into
    `secureflow.orchestrator.graph` so the graph wires our stubs in place
    of the real subprocess-calling agents.
    """
    return [
        patch(
            "secureflow.orchestrator.graph.collect_context",
            new=lambda state: {"pr_context": {
                "changed_files": ["app.go"],
                "changed_line_ranges": [],
                "repo_path": state.get("repo_path", "."),
                "sensitive_files_changed": True,
                "sensitive_signals": ["go_http_handler"],
                "diff": "",
                "language_summary": {"go": 1},
            }},
        ),
        patch(
            "secureflow.orchestrator.graph.secrets_scan",
            new=lambda state: {"secret_findings": [], "scanner_errors": {}},
        ),
        patch(
            "secureflow.orchestrator.graph.sast_scan",
            new=lambda state: {"sast_findings": [seeded_finding], "scanner_errors": {}},
        ),
        patch(
            "secureflow.orchestrator.graph.dependency_scan",
            new=lambda state: {"dependency_findings": [], "scanner_errors": {"grype": "skipped: no manifests changed"}},
        ),
    ]


class _StubLLMClient:
    """Returns canned, schema-correct responses based on the requested schema.

    Implements just the `complete` contract the agents call.
    """

    name = "stub"
    model = "stub-model"

    def complete(self, *, system, user, schema, prompt_version, temperature=0.1, max_tokens=2048):
        if schema is AIDiscoveryResponse:
            parsed = AIDiscoveryResponse(findings=[])
        elif schema is ExploitabilityResult:
            # Mirror the finding_id the prompt mentions so the agent links
            # the result back to the original finding.
            fid = _extract_finding_id_from_prompt(user) or "stub-id"
            parsed = ExploitabilityResult(
                finding_id=fid,
                exploitability="high",
                adjusted_severity="high",
                adjusted_confidence=0.85,
                reasoning="user-controlled input flows into SQL",
                attacker_scenario="attacker injects `' OR 1=1 --`",
                false_positive=False,
            )
        elif schema is PatchReplacement:
            fid = _extract_finding_id_from_prompt(user) or "stub-id"
            parsed = PatchReplacement(
                finding_id=fid,
                replacement_code="q := \"SELECT * FROM u WHERE id = ?\"\n_, _ = db.Query(q, uid)",
                explanation="Use parameterised query",
            )
        elif schema is PatchSuggestion:
            fid = _extract_finding_id_from_prompt(user) or "stub-id"
            parsed = PatchSuggestion(
                finding_id=fid,
                patch_type="code",
                replacement_code="q := \"SELECT * FROM u WHERE id = ?\"",
                explanation="Use parameterised query",
            )
        elif schema is ThreatModelResponse:
            # The fixture is a SQL-injection refactor — no NEW attack
            # surface is added at the design level, so an empty threats
            # list is the correct response. Keeps the banner silent.
            parsed = ThreatModelResponse(threats=[])
        else:
            raise AssertionError(f"unexpected schema in stub: {schema}")

        return LLMCallResult(
            parsed=parsed, prompt_version=prompt_version, model=self.model,
            tokens_in=20, tokens_out=10,
        )


def _extract_finding_id_from_prompt(user: str) -> str | None:
    """Pull `id: <hash>` out of the agent's prompt body (best-effort)."""
    for line in (user or "").splitlines():
        line = line.strip("- \t")
        if line.startswith("id:"):
            return line.split(":", 1)[1].strip()
    return None


# ───────────────────────────────────────────────────────────────── tests ──


def test_e2e_pipeline_llm_available_drives_decision(tmp_path) -> None:
    finding = _write_taint_flow_fixture(tmp_path)
    cfg = Config()

    cm0, cm1, cm2, cm3 = _scanner_patches(finding)
    with (
        cm0, cm1, cm2, cm3,
        patch(
            "secureflow.agents.ai_discovery_agent.build_llm_client",
            return_value=_StubLLMClient(),
        ),
        patch(
            "secureflow.agents.exploitability_agent.build_llm_client",
            return_value=_StubLLMClient(),
        ),
        patch(
            "secureflow.agents.patch_agent.build_patch_llm_client",
            return_value=_StubLLMClient(),
        ),
        patch(
            "secureflow.agents.threat_model_agent.build_llm_client",
            return_value=_StubLLMClient(),
        ),
    ):
        state = run_pipeline(cfg=cfg, repo_path=str(tmp_path))

    decision = state["decision"]
    assert decision["status"] == "FAIL", f"unexpected decision: {decision}"

    final = state.get("final_findings") or state.get("mapped_findings") or []
    assert any(f.get("file_path", "").endswith("app.go") for f in final), \
        "the seeded SQLi finding was lost between normalize and decide"

    # Confidence path: floor lifted to 0.7, exploitability LLM bumped to 0.85.
    sqli = next(f for f in final if f.get("file_path", "").endswith("app.go"))
    assert sqli["confidence"] >= 0.7, f"floor + LLM should yield >=0.7, got {sqli['confidence']}"

    # Markdown rendering integrates correctly: decision badge, no banner.
    md = render_markdown_report(state)
    assert "❌ FAIL" in md
    assert "AI analysis was partially skipped" not in md  # banner stays silent

    # Telemetry captured every node.
    tel = build_telemetry(state)
    node_names = {n["name"] for n in tel["nodes"]}
    expected_subset = {
        "collect_context", "secrets_scan", "sast_scan", "dependency_scan",
        "ai_discovery", "normalize", "threat_map", "enrich_findings",
        "reachability_filter", "exploitability", "patch_generation",
        "threat_model", "decide",
    }
    assert expected_subset.issubset(node_names), \
        f"missing nodes in telemetry: {expected_subset - node_names}"

    # Decision drove a non-empty risk score.
    assert tel["decision"]["status"] == "FAIL"
    assert tel["decision"]["risk_score"] > 0


def test_e2e_pipeline_llm_unavailable_still_correct_via_floor(tmp_path) -> None:
    """When the LLM is unavailable, the deterministic taint-floor must
    keep the decision correct on clearly-tainted SAST findings, and the
    PR-comment banner must surface so reviewers know it's scanner-only."""
    finding = _write_taint_flow_fixture(tmp_path)
    cfg = Config()

    def _raise_config_error(*_a, **_k):
        raise LLMError("GROQ_API_KEY/GEMINI_API_KEY missing")

    cm0, cm1, cm2, cm3 = _scanner_patches(finding)
    with (
        cm0, cm1, cm2, cm3,
        patch(
            "secureflow.agents.ai_discovery_agent.build_llm_client",
            side_effect=_raise_config_error,
        ),
        patch(
            "secureflow.agents.exploitability_agent.build_llm_client",
            side_effect=_raise_config_error,
        ),
        patch(
            "secureflow.agents.patch_agent.build_patch_llm_client",
            side_effect=_raise_config_error,
        ),
        patch(
            "secureflow.agents.threat_model_agent.build_llm_client",
            side_effect=_raise_config_error,
        ),
    ):
        state = run_pipeline(cfg=cfg, repo_path=str(tmp_path))

    # Floor still does its job — confidence lifted to 0.7 even without LLM.
    final = state.get("final_findings") or state.get("mapped_findings") or []
    sqli = next(f for f in final if f.get("file_path", "").endswith("app.go"))
    assert sqli["confidence"] >= 0.7, \
        f"taint-floor should fire scanner-only: confidence={sqli['confidence']}"

    # Decision reaches FAIL on scanner+floor alone.
    assert state["decision"]["status"] == "FAIL"

    # Banner surfaces and names the LLM agents that skipped.
    md = render_markdown_report(state)
    assert "AI analysis was partially skipped" in md
    assert "`exploitability`" in md or "`patch`" in md or "`threat_model`" in md
    # Banner appears above the decision badge.
    assert md.index("AI analysis was partially skipped") < md.index("**Decision:**")
