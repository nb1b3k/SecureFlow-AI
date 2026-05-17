"""Aggregate metrics across the scenario corpus.

The point of these numbers is the resume bullet:
- "recall preserved while FP rate fell from X% to Y%"
- "AI Discovery added Z findings missed by scanners alone"
- "patch validation marked W of suggested patches verified-clean"
"""

from __future__ import annotations

from dataclasses import dataclass

from secureflow.eval.schema import PipelineRun, ScenarioResult


@dataclass
class Aggregate:
    """Aggregate metrics for one pipeline mode across the corpus."""

    scenarios: int
    total_tp: int
    total_fp: int
    total_fn: int
    decisions_correct: int
    avg_latency_ms: int
    total_tokens_in: int
    total_tokens_out: int
    total_llm_calls: int
    patches_attempted: int
    patches_verified: int

    @property
    def precision(self) -> float:
        denom = self.total_tp + self.total_fp
        return self.total_tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.total_tp + self.total_fn
        return self.total_tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def decision_correctness(self) -> float:
        return self.decisions_correct / self.scenarios if self.scenarios else 0.0


def aggregate_for_mode(
    results: list[ScenarioResult], attribute: str
) -> Aggregate | None:
    """Aggregate one pipeline mode across all scenarios.

    `attribute` is either `"scanners_only"` or `"secureflow_full"`.
    Returns None when no scenario produced that mode's run.
    """
    runs: list[PipelineRun] = [
        getattr(s, attribute) for s in results if getattr(s, attribute) is not None
    ]
    if not runs:
        return None
    return Aggregate(
        scenarios=len(runs),
        total_tp=sum(r.true_positives for r in runs),
        total_fp=sum(r.false_positives for r in runs),
        total_fn=sum(r.false_negatives for r in runs),
        decisions_correct=sum(1 for r in runs if r.decision_correct),
        avg_latency_ms=int(sum(r.latency_ms for r in runs) / len(runs)),
        total_tokens_in=sum(r.tokens_in for r in runs),
        total_tokens_out=sum(r.tokens_out for r in runs),
        total_llm_calls=sum(r.llm_calls for r in runs),
        patches_attempted=sum(r.patches_attempted for r in runs),
        patches_verified=sum(r.patches_verified for r in runs),
    )


@dataclass
class Delta:
    """Difference between scanners_only and secureflow_full aggregates."""

    fp_reduced: int
    fp_reduction_pct: float
    tp_uplift: int
    recall_delta: float
    decision_correctness_delta: float
    extra_latency_ms: int
    extra_tokens_in: int
    extra_tokens_out: int


def delta(
    scanners_only: Aggregate | None, full: Aggregate | None
) -> Delta | None:
    """How much did adding the LLM layers change the numbers?"""
    if scanners_only is None or full is None:
        return None
    fp_reduced = scanners_only.total_fp - full.total_fp
    fp_reduction_pct = (
        (fp_reduced / scanners_only.total_fp * 100.0) if scanners_only.total_fp else 0.0
    )
    return Delta(
        fp_reduced=fp_reduced,
        fp_reduction_pct=fp_reduction_pct,
        tp_uplift=full.total_tp - scanners_only.total_tp,
        recall_delta=full.recall - scanners_only.recall,
        decision_correctness_delta=full.decision_correctness - scanners_only.decision_correctness,
        extra_latency_ms=full.avg_latency_ms - scanners_only.avg_latency_ms,
        extra_tokens_in=full.total_tokens_in - scanners_only.total_tokens_in,
        extra_tokens_out=full.total_tokens_out - scanners_only.total_tokens_out,
    )
