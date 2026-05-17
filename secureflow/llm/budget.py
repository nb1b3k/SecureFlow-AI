"""Per-PR LLM cost guardrails.

The orchestrator creates one `BudgetTracker` and passes it to every node
that does LLM work. When the tracker says we're over budget, the node
short-circuits and the orchestrator routes around it; the report records
that AI work was skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secureflow.config import LimitsConfig


class BudgetExceededError(RuntimeError):
    """Raised when a planned LLM call would exceed the PR-level budget."""


@dataclass
class BudgetTracker:
    """Tracks tokens and call counts against `LimitsConfig` thresholds."""

    limits: LimitsConfig
    tokens_in: int = 0
    tokens_out: int = 0
    llm_calls: int = 0
    skipped_reason: str | None = field(default=None, init=False)

    def can_proceed(self, *, estimated_tokens: int = 0) -> bool:
        """Return False if a call of `estimated_tokens` would breach the cap."""
        if self.llm_calls >= self.limits.max_llm_calls_per_pr:
            self.skipped_reason = (
                f"max_llm_calls_per_pr={self.limits.max_llm_calls_per_pr} reached"
            )
            return False
        projected = self.tokens_in + self.tokens_out + estimated_tokens
        if projected > self.limits.max_tokens_per_pr:
            self.skipped_reason = (
                f"max_tokens_per_pr={self.limits.max_tokens_per_pr} would be exceeded"
            )
            return False
        return True

    def reserve(self, *, estimated_tokens: int = 0) -> None:
        """Same as `can_proceed` but raises `BudgetExceededError` on breach."""
        if not self.can_proceed(estimated_tokens=estimated_tokens):
            raise BudgetExceededError(self.skipped_reason or "budget exceeded")

    def record(self, *, tokens_in: int, tokens_out: int) -> None:
        """Record an actual completed LLM call."""
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.llm_calls += 1

    def snapshot(self) -> dict[str, int]:
        """Return a plain dict suitable for `state.budget_used` reduce."""
        return {
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "llm_calls": self.llm_calls,
        }
