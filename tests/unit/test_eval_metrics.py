"""Unit tests for eval metrics aggregation."""

from __future__ import annotations

from secureflow.eval.metrics import aggregate_for_mode, delta
from secureflow.eval.schema import (
    ExpectedLabel,
    PipelineRun,
    ScenarioExpected,
    ScenarioResult,
)


def _expected() -> ScenarioExpected:
    return ScenarioExpected(
        scenario_id="s",
        labels=[ExpectedLabel(id="l1", type="sql_injection", file="a.py")],
        expected_decision="FAIL",
    )


def _run(mode: str, *, tp: int, fp: int, fn: int, decision: str = "FAIL", correct: bool = True,
         latency: int = 1000, tin: int = 0, tout: int = 0, pa: int = 0, pv: int = 0) -> PipelineRun:
    return PipelineRun(
        mode=mode, decision=decision, decision_correct=correct, risk_score=50,
        total_findings=tp + fp, true_positives=tp, false_positives=fp,
        false_negatives=fn, latency_ms=latency, tokens_in=tin, tokens_out=tout,
        patches_attempted=pa, patches_verified=pv,
    )


def test_aggregate_computes_precision_recall_f1() -> None:
    results = [
        ScenarioResult(
            scenario_id="a", expected=_expected(),
            secureflow_full=_run("secureflow_full", tp=3, fp=1, fn=1),
        ),
        ScenarioResult(
            scenario_id="b", expected=_expected(),
            secureflow_full=_run("secureflow_full", tp=2, fp=0, fn=0),
        ),
    ]
    agg = aggregate_for_mode(results, "secureflow_full")
    assert agg is not None
    # tp=5, fp=1 → precision = 5/6
    assert abs(agg.precision - 5/6) < 1e-6
    # tp=5, fn=1 → recall = 5/6
    assert abs(agg.recall - 5/6) < 1e-6
    # f1 = harmonic mean = same here = 5/6
    assert abs(agg.f1 - 5/6) < 1e-6


def test_aggregate_decision_correctness() -> None:
    results = [
        ScenarioResult(
            scenario_id="a", expected=_expected(),
            secureflow_full=_run("secureflow_full", tp=1, fp=0, fn=0, correct=True),
        ),
        ScenarioResult(
            scenario_id="b", expected=_expected(),
            secureflow_full=_run("secureflow_full", tp=0, fp=0, fn=1, correct=False),
        ),
    ]
    agg = aggregate_for_mode(results, "secureflow_full")
    assert agg is not None
    assert agg.decisions_correct == 1
    assert agg.decision_correctness == 0.5


def test_aggregate_returns_none_when_mode_missing() -> None:
    """A scenario without that mode populated → not counted; if none have it, None."""
    results = [
        ScenarioResult(scenario_id="a", expected=_expected()),
    ]
    assert aggregate_for_mode(results, "secureflow_full") is None
    assert aggregate_for_mode(results, "scanners_only") is None


def test_delta_reports_fp_reduction_and_tp_uplift() -> None:
    results = [
        ScenarioResult(
            scenario_id="x", expected=_expected(),
            scanners_only=_run("scanners_only", tp=1, fp=5, fn=2),
            secureflow_full=_run("secureflow_full", tp=3, fp=1, fn=0),
        ),
    ]
    so = aggregate_for_mode(results, "scanners_only")
    sf = aggregate_for_mode(results, "secureflow_full")
    d = delta(so, sf)
    assert d is not None
    # FP went from 5 to 1 → reduced by 4
    assert d.fp_reduced == 4
    assert d.fp_reduction_pct == 80.0
    # TP went from 1 to 3 → uplift +2
    assert d.tp_uplift == 2


def test_zero_findings_zero_division_safe() -> None:
    agg = aggregate_for_mode(
        [
            ScenarioResult(
                scenario_id="empty", expected=_expected(),
                secureflow_full=_run("secureflow_full", tp=0, fp=0, fn=0),
            ),
        ],
        "secureflow_full",
    )
    assert agg is not None
    assert agg.precision == 0.0
    assert agg.recall == 0.0
    assert agg.f1 == 0.0
