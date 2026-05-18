"""Pydantic models for the evaluation harness.

`ScenarioExpected` mirrors the on-disk `expected.yaml` written next to
each fixture. `PipelineRun` / `ScenarioResult` are the in-memory results
the runner produces.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DecisionStatus = Literal["PASS", "WARN", "FAIL"]
PipelineMode = Literal["scanners_only", "secureflow_full"]


class ExpectedLabel(BaseModel):
    """Ground-truth label for one intended finding in a fixture."""

    model_config = ConfigDict(extra="ignore")

    id: str
    type: str = Field(
        description=(
            "Human-readable category (sql_injection, hardcoded_secret, "
            "missing_authorization, ...). Mapped to scanner rule IDs + AI "
            "title keywords via `secureflow/eval/label_aliases.yaml`."
        )
    )
    file: str
    line_range: list[int] | None = Field(
        default=None,
        description="[start_line, end_line]. Optional for findings without a location.",
    )
    expected_severity: str | None = None
    expected_decision_contribution: DecisionStatus | None = None

    # Optional metadata used by the dependency scenarios
    package: str | None = None
    version: str | None = None


class ScenarioExpected(BaseModel):
    """The full on-disk `expected.yaml` payload for one fixture."""

    model_config = ConfigDict(extra="ignore")

    scenario_id: str
    description: str = ""
    labels: list[ExpectedLabel] = Field(default_factory=list)
    expected_decision: DecisionStatus
    expected_minimum_recall: float = Field(default=0.0, ge=0.0, le=1.0)
    expected_maximum_fp: int | None = None
    notes: str = ""


class PipelineRun(BaseModel):
    """Outcome of running one pipeline (scanners_only or full) on a scenario."""

    model_config = ConfigDict(extra="ignore")

    mode: PipelineMode
    decision: DecisionStatus
    decision_correct: bool
    risk_score: int
    total_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    # W22 — additional findings on the same target as an already-matched
    # primary (e.g. extra CVEs on a labeled package; extra Checkov sub-
    # checks on a labeled IaC resource). Neither TP nor FP — credited
    # separately so the FP count reflects real false positives instead
    # of multi-finding-per-label noise.
    secondary: int = 0
    matched_label_ids: list[str] = Field(default_factory=list)
    unmatched_label_ids: list[str] = Field(default_factory=list)
    latency_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    llm_calls: int = 0
    patches_attempted: int = 0
    patches_verified: int = 0
    scanner_errors: dict[str, str] = Field(default_factory=dict)

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)


class ScenarioResult(BaseModel):
    """Per-scenario result combining both pipelines."""

    model_config = ConfigDict(extra="ignore")

    scenario_id: str
    expected: ScenarioExpected
    scanners_only: PipelineRun | None = None
    secureflow_full: PipelineRun | None = None
    notes: list[str] = Field(default_factory=list)
