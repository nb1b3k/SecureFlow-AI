"""SecureFlow AI evaluation harness.

Runs the full pipeline (and a `scanners_only` baseline) against a corpus of
labeled vulnerable-PR fixtures, computes recall / precision / FP reduction /
decision correctness, and produces a Markdown report that drops into the
project's README.

See `design/04_evaluation_harness.md`.
"""

from secureflow.eval.schema import (
    ExpectedLabel,
    PipelineRun,
    ScenarioExpected,
    ScenarioResult,
)

__all__ = ["ExpectedLabel", "PipelineRun", "ScenarioExpected", "ScenarioResult"]
