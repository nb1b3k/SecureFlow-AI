"""Semgrep subprocess wrapper for SAST findings."""

from __future__ import annotations

import json

from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import run

log = get_logger("semgrep")


def run_semgrep(repo_path: str, *, config: str = "auto") -> list[dict]:
    """Run semgrep with the given ruleset and return raw findings.

    Semgrep's exit code is 1 when it finds issues; not an error for us.

    Ignore-flag rationale:
    - `--no-git-ignore`: scan files even if they're untracked or under a
      gitignored path. Without this, scanning a sub-path under a git repo
      surprises users with "0 targets scanned".
    - `--x-ignore-semgrepignore-files`: Semgrep ships a default ignore set
      that excludes `tests/**` and `fixtures/**`. When a user explicitly
      passes `--repo` pointing at one of those, we want to honor the
      explicit choice and not silently produce zero findings.
    """
    r = run(
        [
            "semgrep", "scan",
            "--config", config,
            "--json", "--quiet",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            repo_path,
        ],
        timeout=240,
    )
    if r.timed_out:
        log.warning("semgrep timed out after 240s")
        return []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        log.warning("semgrep produced non-JSON output: %s", r.stderr[:300])
        return []
    return list(data.get("results", []))
