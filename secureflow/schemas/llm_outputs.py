"""Schemas for raw LLM responses.

Kept separate from `Finding` so LLM output stays strictly typed without
forcing the rest of the codebase to make every `Finding` field optional.
The agent layer merges these into `Finding` objects.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secureflow.schemas.finding import Severity


class AIDiscoveryItem(BaseModel):
    """One vulnerability proposed by the AI Discovery agent.

    Tolerance-mode: every field has a sensible default, and `confidence`
    is coerced from common LLM-sloppiness shapes. Pre-prod evidence:
    in a 10-item response, DeepSeek occasionally drops `evidence` or
    `exploit_scenario` for one item. Without these defaults the whole
    response fails schema validation and cascades through chain
    failover, ending in a "AI analysis was partially skipped" banner
    in the bot comment. With defaults, one malformed item gets empty
    strings (still useful to the reviewer because `title` + `file_path`
    almost always come through) and the other 9 items go through.
    """

    model_config = ConfigDict(extra="ignore")

    title: str = ""
    description: str = ""
    file_path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    severity: Severity = "medium"
    confidence: float = 0.5
    evidence: str = ""
    exploit_scenario: str = ""
    recommendation: str = ""
    suggested_decision: Literal["PASS", "WARN", "FAIL"] = "WARN"

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v):
        """Coerce `confidence` from the shapes LLMs occasionally emit.

        Same logic as `ThreatModelItem._clamp_confidence` — accepts
        numbers outside [0, 1], qualitative strings ("high"/"medium"/
        "low"), and None. Clamps to [0, 1].
        """
        if v is None:
            return 0.5
        if isinstance(v, str):
            low = v.strip().lower()
            if low in ("high", "very high"):
                return 0.9
            if low in ("medium",):
                return 0.6
            if low in ("low",):
                return 0.3
            try:
                v = float(low)
            except ValueError:
                return 0.5
        try:
            f = float(v)
        except (TypeError, ValueError):
            return 0.5
        if f > 1.0 and f <= 100.0:
            f = f / 100.0
        return max(0.0, min(1.0, f))


class AIDiscoveryResponse(BaseModel):
    """Top-level wrapper the AI Discovery prompt is constrained to."""

    model_config = ConfigDict(extra="ignore")

    findings: list[AIDiscoveryItem] = Field(default_factory=list)


StrideCategory = Literal[
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
]

ChangeType = Literal[
    "new_endpoint",
    "new_admin_route",
    "new_auth_logic",
    "auth_logic_change",
    "new_external_integration",
    "new_data_export",
    "new_file_upload",
    "new_payment_logic",
    "new_trust_boundary",
    "new_cross_tenant_path",
    "new_iac_resource",
    "increased_blast_radius",
    "other",
]


class ThreatModelItem(BaseModel):
    """One design-level threat introduced by the PR.

    Output of the Threat Modeling Delta agent. Independent of in-code
    vulnerability findings — a PR can pass all code scans and still
    introduce a design-level threat (e.g. "this PR adds an admin endpoint
    with no authorization middleware in front of it" — semgrep wouldn't
    flag the new function, but a threat model review would).

    Bound to evidence by `file_path` (and optionally `start_line`) so
    reviewers can navigate from the bot comment straight to the code
    that introduced the change. `evidence_excerpt` carries the lines the
    LLM cited so its claim is auditable.
    """

    # Tolerance-mode: every field has a sensible default and list-shaped
    # fields coerce common LLM-sloppiness inputs (empty-string, single
    # string, None) into a valid list. Pre-prod evidence: on a 12-threat
    # response, DeepSeek occasionally drops `confidence` or returns
    # `abuse_cases: ""` for one item. Without these tolerances the
    # whole response fails schema validation, cascades through the
    # chain failover, and ends in a skip-banner. With them, the one
    # malformed item gets its sane defaults and the response goes
    # through cleanly.
    model_config = ConfigDict(extra="ignore")

    change_type: ChangeType = "other"
    title: str = ""
    description: str = Field(
        default="",
        description="What the PR introduced or modified at the design level.",
    )
    file_path: str = Field(
        default="",
        description="The file that introduced the change. The threat is less "
        "useful without it; the markdown report just shows '—' for location.",
    )
    start_line: int | None = None
    evidence_excerpt: str = Field(
        default="",
        description="Short excerpt of the changed code (or IaC) that supports "
        "this threat — keeps the LLM honest and lets the reviewer audit the claim.",
    )
    stride: list[StrideCategory] = Field(
        default_factory=list,
        description="STRIDE categories that apply to this change.",
    )
    abuse_cases: list[str] = Field(
        default_factory=list,
        description="Concrete misuse scenarios an attacker could attempt against "
        "the new surface.",
    )
    mitigations: list[str] = Field(
        default_factory=list,
        description="Specific controls the reviewer should require before merge "
        "(authz check, rate limit, input validation, IAM scope, etc.).",
    )
    severity: Severity = "medium"
    # Default 0.5 (medium confidence) when the LLM forgets the field;
    # this is the most-common shape the schema breaks on. Validator
    # below clamps any out-of-range numeric to [0.0, 1.0].
    confidence: float = 0.5
    suggested_decision: Literal["PASS", "WARN", "FAIL"] = "WARN"

    @field_validator("stride", "abuse_cases", "mitigations", mode="before")
    @classmethod
    def _coerce_lists(cls, v):
        """Coerce common LLM-sloppiness shapes into a list.

        DeepSeek and Groq both occasionally emit a string where the
        schema declares `list[str]` — typically an empty string or a
        single comma-separated string. Rather than fail validation on
        the whole response (and cascade through the chain failover),
        we accept the sloppy shape here and let the agent get on with
        its work.
        """
        if v is None or v == "":
            return []
        if isinstance(v, str):
            # Split on common separators; trim + drop empties.
            parts = [p.strip() for p in v.replace(";", ",").split(",")]
            return [p for p in parts if p]
        return v

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v):
        """Accept the LLM's `confidence` even if it's outside [0, 1].

        Seen pattern: the model emits 0.95 (valid), 95 (meant as 0.95),
        or "high" (meant qualitatively). Coerce to a numeric in range.
        """
        if v is None:
            return 0.5
        if isinstance(v, str):
            low = v.strip().lower()
            if low in ("high", "very high"):
                return 0.9
            if low in ("medium",):
                return 0.6
            if low in ("low",):
                return 0.3
            try:
                v = float(low)
            except ValueError:
                return 0.5
        try:
            f = float(v)
        except (TypeError, ValueError):
            return 0.5
        if f > 1.0 and f <= 100.0:
            f = f / 100.0  # 95 → 0.95
        return max(0.0, min(1.0, f))


class ThreatModelResponse(BaseModel):
    """Top-level wrapper the Threat Modeling Delta prompt is constrained to."""

    model_config = ConfigDict(extra="ignore")

    threats: list[ThreatModelItem] = Field(default_factory=list)


class ExploitabilityResult(BaseModel):
    """The exploitability agent's per-finding adjustment."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str
    exploitability: Literal["none", "low", "medium", "high", "critical"]
    adjusted_severity: Severity
    adjusted_confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    attacker_scenario: str
    false_positive: bool
    false_positive_reason: str | None = None


class PatchReplacement(BaseModel):
    """Tight schema the LLM is constrained to when asked for a patch.

    Why a separate, smaller schema from `PatchSuggestion`:
      - Ollama's `format=<json-schema>` grammar enforcement DOES NOT force
        Optional fields to be present. With small models, an Optional
        `unified_diff` or `replacement_code` simply gets omitted — and the
        model has technically obeyed the schema.
      - This schema has 3 fields, ALL required, with `replacement_code`
        constrained to non-empty. The grammar enforces all three; the
        model literally cannot return an empty patch.

    The orchestrator wraps a `PatchReplacement` into a `PatchSuggestion`
    (`patch_type="code"`, `unified_diff` synthesised by `difflib`) before
    the apply+rescan step.
    """

    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(min_length=1)
    replacement_code: str = Field(min_length=1)
    explanation: str = ""


class PatchReview(BaseModel):
    """Second-opinion LLM verdict on a generated patch.

    The patch agent runs scanner-rescan as the primary verification
    signal: apply the patch to a temp worktree, re-run the originating
    scanner, mark `verified` if the finding clears. That catches the
    "did this fix the flagged rule" question — but it cannot answer:

      - Is the replacement code syntactically valid for the file's
        language, or did the model emit prose / mojibake that happened
        not to match the scanner rule? (Pre-prod evidence: OpenRouter
        free returned multi-language gibberish that scanners ignored.)
      - Does the replacement preserve the original code's
        indentation / structure / naming style so the file stays
        readable and parseable?
      - For AI-only findings (no scanner to rerun), is the fix even
        relevant to the described vulnerability?

    `PatchReview` is the schema for a separate LLM call that answers
    those questions. The patch agent folds the verdict into
    `patch_status` (e.g. scanner-verified + review-rejected →
    downgrade to `unverified`; AI-only + review-approved → upgrade
    from `not_applicable` to `verified`).
    """

    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(min_length=1)
    addresses_vulnerability: bool = Field(
        description="True iff the replacement code visibly mitigates the "
        "specific vulnerability described by the finding (e.g. "
        "parameterised the SQL, narrowed the IAM wildcard, etc.)."
    )
    matches_code_context: bool = Field(
        description="True iff the replacement is valid code in the file's "
        "language, preserves indentation/style, and would parse without "
        "syntax errors when spliced into the file at the finding's lines."
    )
    concerns: list[str] = Field(
        default_factory=list,
        description="Specific issues with the patch — must be populated "
        "whenever either boolean is false. Short imperative phrasing.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    verdict: Literal["approve", "reject", "uncertain"]


class PatchSuggestion(BaseModel):
    """A patch the LLM proposes for a finding.

    The LLM may answer in either form:
      - `unified_diff` — a real git-style unified diff ready to apply.
        Preferred for strong models.
      - `replacement_code` — just the new line(s) that should replace the
        flagged region (`finding.start_line..finding.end_line`). The
        orchestrator synthesises the diff with `difflib`. This is the
        reliable path for smaller local models that struggle with diff
        formatting but can still write the secure code itself.
    """

    model_config = ConfigDict(extra="ignore")

    finding_id: str
    patch_type: Literal["code", "dependency", "configuration", "manual"]
    unified_diff: str | None = None
    replacement_code: str | None = None
    explanation: str
    side_effects: str = ""
    verification_steps: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_actionable_payload_for_non_manual(self) -> PatchSuggestion:
        # `manual` is the only patch_type that may legitimately omit both
        # the diff and the replacement code. Everything else must carry an
        # actionable payload so the orchestrator can apply it; otherwise
        # the LLM client's corrective-retry kicks in.
        if self.patch_type == "manual":
            return self
        has_diff = bool((self.unified_diff or "").strip())
        has_replacement = bool((self.replacement_code or "").strip())
        if not (has_diff or has_replacement):
            raise ValueError(
                f"patch_type={self.patch_type!r} requires either a non-empty "
                "`unified_diff` OR a non-empty `replacement_code` (use "
                "patch_type='manual' if neither is possible)"
            )
        return self
