"""Grype subprocess wrapper for dependency-vulnerability scanning."""

from __future__ import annotations

import json

from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import run

log = get_logger("grype")


def run_grype(repo_path: str) -> list[dict]:
    """Run grype against the repo and return its `matches` array."""
    r = run(["grype", f"dir:{repo_path}", "-o", "json"], timeout=300)
    if r.timed_out:
        log.warning("grype timed out after 300s")
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        log.warning("grype produced non-JSON output: %s", r.stderr[:300])
        return []
    return list(data.get("matches", []))
