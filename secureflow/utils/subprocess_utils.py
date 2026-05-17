"""Uniform subprocess execution for scanner runners.

Centralizes:
- timeout handling,
- "tool not installed" detection,
- structured logging of command lines (with arg masking),
- predictable error semantics so the orchestrator can downgrade gracefully.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from secureflow.utils.logging import get_logger
from secureflow.utils.secret_masker import mask

log = get_logger("subprocess")


class ToolNotFoundError(RuntimeError):
    """Raised when an external binary (semgrep, gitleaks, ...) is missing."""


@dataclass
class ProcResult:
    """Outcome of a subprocess invocation."""

    cmd: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """A run with returncode 0. Scanners may use non-zero to indicate findings."""
        return self.returncode == 0 and not self.timed_out


def which(binary: str) -> str | None:
    """Return the absolute path to `binary` or None if missing."""
    return shutil.which(binary)


def _coerce_str(raw: object) -> str:
    """subprocess streams can be str (text=True), bytes (text=False), or None.

    Normalize to str so callers don't crash on edge cases like a tool that
    closes stdout without writing anything.
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def run(
    cmd: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: float | None = 120.0,
    check: bool = False,
    input_data: str | bytes | None = None,
) -> ProcResult:
    """Run `cmd` and capture stdout/stderr.

    Does NOT raise on non-zero exit unless `check=True`. Many scanners return
    non-zero when they find issues, which is not an error.
    """
    if not cmd:
        raise ValueError("empty command")
    binary = cmd[0]
    if which(binary) is None:
        raise ToolNotFoundError(binary)

    safe_cmd = mask(" ".join(cmd))
    log.debug("subprocess.run %s (cwd=%s, timeout=%s)", safe_cmd, cwd, timeout)

    timed_out = False
    try:
        text_mode = isinstance(input_data, (str, type(None)))
        # On Windows, text=True without an explicit encoding defaults to
        # cp1252, which crashes on any non-ASCII byte in scanner output
        # (e.g. grype embeds ANSI/unicode in warnings). Force UTF-8 with
        # replacement so scanner output never kills the reader thread.
        proc = subprocess.run(
            list(cmd),
            cwd=cwd,
            input=input_data,
            capture_output=True,
            text=text_mode,
            encoding="utf-8" if text_mode else None,
            errors="replace" if text_mode else None,
            timeout=timeout,
            check=False,
        )
        stdout = _coerce_str(proc.stdout)
        stderr = _coerce_str(proc.stderr)
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = (
            e.stdout.decode("utf-8", errors="replace")
            if isinstance(e.stdout, (bytes, bytearray))
            else (e.stdout or "")
        )
        stderr = (
            e.stderr.decode("utf-8", errors="replace")
            if isinstance(e.stderr, (bytes, bytearray))
            else (e.stderr or "")
        )
        rc = 124  # convention: timeout

    result = ProcResult(
        cmd=tuple(cmd),
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )
    if check and not result.ok:
        raise subprocess.CalledProcessError(
            rc, list(cmd), output=stdout, stderr=stderr
        )
    return result
