"""Scenario runner — executes both pipelines (scanners_only + full) on a fixture.

The runner is a thin orchestrator. It builds two `Config` instances (one
with LLM agents disabled, one full), invokes the LangGraph pipeline for
each, and folds the resulting state into a `PipelineRun` per mode.
"""

from __future__ import annotations

import time

from secureflow.config import Config
from secureflow.eval.loader import Scenario
from secureflow.eval.matcher import match_findings_to_labels
from secureflow.eval.schema import PipelineMode, PipelineRun, ScenarioResult
from secureflow.orchestrator import run_pipeline
from secureflow.utils.logging import get_logger

log = get_logger("eval.runner")


def _eval_reachability(cfg: Config) -> Config:
    """For eval runs, override reachability so fixture paths are not dampened.

    In production, files under `tests/` / `fixtures/` get classified as
    `unreachable` and their findings get confidence-capped (correctly —
    you don't want CI to FAIL on a SQLi in a unit test). The eval corpus
    lives under `tests/fixtures/...` but the fixture file IS the runtime
    from the scenario's perspective. Strip the dampening so eval findings
    keep their scanner-reported confidence.
    """
    return cfg.model_copy(update={
        "reachability": cfg.reachability.model_copy(update={
            "excluded_runtime_dirs": [],
        }),
    })


def _scanners_only_config(cfg: Config) -> Config:
    """Disable LLM agents so we measure the deterministic pipeline baseline."""
    cfg = _eval_reachability(cfg)
    return cfg.model_copy(update={
        "ai_discovery": cfg.ai_discovery.model_copy(update={"enabled": False}),
        "limits": cfg.limits.model_copy(update={
            "max_findings_to_exploit_check": 0,
            "max_patches_per_pr": 0,
        }),
    })


def _full_config(cfg: Config) -> Config:
    """The configured pipeline — LLM agents enabled per .secureflow.yml."""
    return _eval_reachability(cfg)


def run_scenario(
    scenario: Scenario,
    *,
    base_config: Config | None = None,
    modes: tuple[PipelineMode, ...] = ("scanners_only", "secureflow_full"),
) -> ScenarioResult:
    """Run the requested pipeline modes against one fixture, return per-mode results."""
    base = base_config or Config()
    result = ScenarioResult(scenario_id=scenario.scenario_id, expected=scenario.expected)

    for mode in modes:
        cfg = _scanners_only_config(base) if mode == "scanners_only" else _full_config(base)
        run = _run_one(scenario, cfg, mode)
        if mode == "scanners_only":
            result.scanners_only = run
        else:
            result.secureflow_full = run

    return result


def _run_one(scenario: Scenario, cfg: Config, mode: PipelineMode) -> PipelineRun:
    start = time.monotonic()
    state = run_pipeline(cfg=cfg, repo_path=str(scenario.repo_path))
    elapsed_ms = int((time.monotonic() - start) * 1000)

    final = state.get("final_findings") or state.get("mapped_findings") or []
    decision = state.get("decision") or {}
    budget = state.get("budget_used") or {}

    match = match_findings_to_labels(
        final, scenario.expected.labels, scenario_repo=scenario.repo_path,
    )

    patches_attempted = sum(
        1 for f in final
        if f.get("patch_status") in {"verified", "unverified", "conflict", "suggested"}
    )
    patches_verified = sum(1 for f in final if f.get("patch_status") == "verified")

    decision_status = decision.get("status", "PASS")
    return PipelineRun(
        mode=mode,
        decision=decision_status,
        decision_correct=(decision_status == scenario.expected.expected_decision),
        risk_score=decision.get("risk_score", 0),
        total_findings=len(final),
        true_positives=match.tp,
        false_positives=match.fp,
        false_negatives=match.fn,
        matched_label_ids=match.matched_label_ids,
        unmatched_label_ids=match.unmatched_label_ids,
        latency_ms=elapsed_ms,
        tokens_in=int(budget.get("tokens_in", 0) or 0),
        tokens_out=int(budget.get("tokens_out", 0) or 0),
        llm_calls=int(budget.get("llm_calls", 0) or 0),
        patches_attempted=patches_attempted,
        patches_verified=patches_verified,
        scanner_errors=dict(state.get("scanner_errors") or {}),
    )


def run_corpus(
    scenarios: list[Scenario],
    *,
    base_config: Config | None = None,
    modes: tuple[PipelineMode, ...] = ("scanners_only", "secureflow_full"),
) -> list[ScenarioResult]:
    """Run all scenarios sequentially. Returns one ScenarioResult per scenario."""
    results: list[ScenarioResult] = []
    for i, sc in enumerate(scenarios, 1):
        log.info(
            "scenario %d/%d: %s",
            i, len(scenarios), sc.scenario_id,
            extra={"scenario_id": sc.scenario_id},
        )
        results.append(run_scenario(sc, base_config=base_config, modes=modes))
    return results
