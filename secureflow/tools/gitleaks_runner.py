"""Gitleaks subprocess wrapper for secret detection.

Returns the raw JSON parse. The agent layer normalizes into `Finding`.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import run

log = get_logger("gitleaks")


def run_gitleaks(repo_path: str) -> list[dict]:
    """Run gitleaks on `repo_path` and return its parsed JSON findings.

    We invoke `gitleaks detect --no-git --source <path>`:

    - `--no-git` makes gitleaks scan files as-is rather than walking git
      history. This is the right semantic for PR-review use: the bot cares
      about the new state of the diff, not historical secrets that may
      have already been rotated. It also stops gitleaks from walking up
      from a target sub-directory into a parent git repo (the source of
      our eval's false-attribution where scanning fixture A reported
      findings from fixture B).
    - `--exit-code 0` keeps a non-zero exit (findings present) from being
      treated as an error by our subprocess wrapper.

    Raises `ToolNotFoundError` if gitleaks isn't installed.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        report_path = f.name
    try:
        r = run(
            [
                "gitleaks", "detect",
                "--no-banner",
                "--no-git",
                "--report-format", "json",
                "--report-path", report_path,
                "--source", repo_path,
                "--exit-code", "0",
            ],
            timeout=180,
        )
        if r.returncode not in (0, 1) or r.timed_out:
            log.warning("gitleaks failed: rc=%s err=%s", r.returncode, r.stderr[:300])
        try:
            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            data = []
        if not isinstance(data, list):
            data = []
        return data
    finally:
        Path(report_path).unlink(missing_ok=True)
