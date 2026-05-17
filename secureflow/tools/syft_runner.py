"""Syft subprocess wrapper for SBOM generation (currently unused in Phase 1)."""

from __future__ import annotations

import json

from secureflow.utils.subprocess_utils import run


def run_syft(repo_path: str) -> dict:
    """Generate an SBOM. Returns an empty dict on failure."""
    r = run(["syft", f"dir:{repo_path}", "-o", "json"], timeout=240)
    if r.timed_out:
        return {}
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}
