"""Error classes for the orchestrator.

Terminal errors stop the graph (CLI exits with code 2 — distinct from
FAIL=1). Node-local errors are caught inside the node and recorded in
`state.scanner_errors` so the pipeline continues.
"""

from __future__ import annotations


class OrchestratorError(RuntimeError):
    """Base class for terminal orchestrator failures."""


class ContextError(OrchestratorError):
    """Failed to build PR context — can't proceed."""


class DecideError(OrchestratorError):
    """Failed to produce a decision."""


class ReportError(OrchestratorError):
    """Failed to produce or post a report."""
