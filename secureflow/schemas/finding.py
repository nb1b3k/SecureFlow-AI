"""The `Finding` schema — canonical representation of a single security issue.

Every scanner, every LLM agent, and the policy engine all read and produce
`Finding` objects. Keep this file boring and stable.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Source = Literal[
    "semgrep", "gitleaks", "grype", "osv", "bandit", "checkov", "ai_discovery", "manual"
]
Severity = Literal["info", "low", "medium", "high", "critical"]
PatchStatus = Literal[
    "none", "suggested", "verified", "unverified", "conflict", "not_applicable"
]
Reachability = Literal["unreachable", "likely_reachable", "unknown"]
Exploitability = Literal["none", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    """A single normalized security finding."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Stable hash, computed by `compute_finding_id`.")
    source: Source
    rule_id: str | None = Field(
        default=None, description="Scanner rule ID where applicable."
    )
    title: str
    description: str

    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = Field(
        default=None, description="Enclosing function/class name when known."
    )

    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str | None = None

    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None

    reachability: Reachability = "unknown"
    exploitability: Exploitability | None = None
    attacker_scenario: str | None = None
    impact: str | None = None

    false_positive: bool = False
    false_positive_reason: str | None = None

    recommendation: str | None = None
    patch_unified_diff: str | None = None
    # The raw replacement text (without diff markers) that the LLM proposed.
    # Stored alongside `patch_unified_diff` so the markdown report can emit
    # a GitHub `suggestion` block in the PR comment — diffs render as code
    # but only `replacement_code` triggers the "Apply suggestion" button
    # when the comment lands on the right review line.
    replacement_code: str | None = None
    patch_explanation: str | None = None
    patch_status: PatchStatus = "none"
    patch_verification_notes: str | None = None

    # Second-opinion LLM review of the generated patch. Populated by the
    # patch agent's review pass (`PatchReview` schema). Optional because
    # AI-only / pre-2026-05-17 findings won't have them and `Finding`
    # ignores extras — so omitting these fields had been quietly losing
    # the review data when the dict round-tripped through Pydantic.
    patch_review_verdict: Literal["approve", "reject", "uncertain"] | None = None
    patch_review_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    patch_review_concerns: list[str] = Field(default_factory=list)

    prompt_version: str | None = Field(
        default=None,
        description="Prompt version that produced LLM-derived fields (if any).",
    )
