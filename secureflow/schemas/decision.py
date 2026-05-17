"""The final CI decision — PASS, WARN, or FAIL."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DecisionStatus = Literal["PASS", "WARN", "FAIL"]


class Decision(BaseModel):
    """Output of the policy engine. Drives CI exit code."""

    model_config = ConfigDict(extra="ignore")

    status: DecisionStatus
    risk_score: int = Field(ge=0, le=100)
    summary: str
    reasons: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)

    skipped_components: list[str] = Field(
        default_factory=list,
        description='Components that did not run, e.g. "ai_discovery: budget_exceeded".',
    )
