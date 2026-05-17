"""Canonical Pydantic schemas. Source of truth for cross-component contracts.

See `design/05_schemas_and_finding_ids.md` for the full spec.
"""

from secureflow.schemas.decision import Decision, DecisionStatus
from secureflow.schemas.finding import (
    Finding,
    PatchStatus,
    Reachability,
    Severity,
    Source,
)
from secureflow.schemas.ids import code_fingerprint, compute_finding_id
from secureflow.schemas.llm_outputs import (
    AIDiscoveryItem,
    AIDiscoveryResponse,
    ExploitabilityResult,
    PatchSuggestion,
)
from secureflow.schemas.pr_context import (
    ChangedLineRange,
    FunctionBoundary,
    PRContext,
)
from secureflow.schemas.state import SecurityReviewState

__all__ = [
    "AIDiscoveryItem",
    "AIDiscoveryResponse",
    "ChangedLineRange",
    "Decision",
    "DecisionStatus",
    "ExploitabilityResult",
    "Finding",
    "FunctionBoundary",
    "PRContext",
    "PatchStatus",
    "PatchSuggestion",
    "Reachability",
    "SecurityReviewState",
    "Severity",
    "Source",
    "code_fingerprint",
    "compute_finding_id",
]
