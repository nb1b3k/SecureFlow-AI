"""Lightweight git operations for building the PR context.

Two operating modes:
- GitHub Actions: read PR base/head from env, diff between them.
- Local: diff against HEAD~1 by default, configurable.

When git isn't available or the repo has no commits, fall back to "scan
the whole working tree" mode so the CLI still produces useful output.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import ToolNotFoundError, run

log = get_logger("git")


@dataclass
class DiffResult:
    base_ref: str | None
    head_ref: str | None
    changed_files: list[str]
    diff_text: str
    fallback_used: bool = False
    # file (forward-slash, repo-relative) -> list of (start_line, end_line)
    # ranges in the *head* version. Empty when diff_text is unavailable.
    changed_line_ranges: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


def is_git_repo(repo_path: str | Path) -> bool:
    p = Path(repo_path) / ".git"
    return p.exists()


def _refs_from_env() -> tuple[str | None, str | None]:
    """Extract (base, head) refs from GitHub Actions environment, if present.

    `pull_request` events: `actions/checkout@v4` leaves the working tree at
    the synthetic merge commit in DETACHED-HEAD state. The PR's head branch
    is NOT locally checked out by name, so `GITHUB_HEAD_REF` (e.g.
    "feature/foo") doesn't resolve as a git ref in CI. The only universally
    valid ref to name for the PR's current commit is `HEAD`.

    The base IS available as `origin/<GITHUB_BASE_REF>` because
    `fetch-depth: 0` in our workflow fetches remote refs. So we diff
    `origin/<base>...HEAD`, which is the PR's net change.

    Push events (no PR): fall back to GITHUB_SHA as head, no base — the
    caller will then use the local HEAD~1 path.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None, None
    base = os.environ.get("GITHUB_BASE_REF") or None
    if base and not base.startswith("origin/"):
        base = f"origin/{base}"
    if base:
        head = "HEAD"
    else:
        head = os.environ.get("GITHUB_SHA") or None
    return base, head


def compute_diff(
    repo_path: str | Path,
    *,
    base: str | None = None,
    head: str | None = None,
) -> DiffResult:
    """Compute changed files and unified diff between `base` and `head`.

    If `base` is None: try GitHub Actions env, else fall back to HEAD~1..HEAD.
    If no git repo or git is missing: list all tracked files and return empty diff.
    """
    repo = str(repo_path)

    if not is_git_repo(repo):
        log.info("not a git repo; scanning whole working tree", extra={"repo": repo})
        all_files = _walk_files(repo)
        return DiffResult(None, None, all_files, "", fallback_used=True)

    env_base, env_head = _refs_from_env()
    base = base or env_base
    head = head or env_head

    try:
        if base and head:
            files = _diff_filenames(repo, f"{base}...{head}")
            diff = _diff_text(repo, f"{base}...{head}")
            return DiffResult(base, head, files, diff, changed_line_ranges=parse_changed_line_ranges(diff))
        # Local fallback: diff vs HEAD~1 if it exists, else against empty tree.
        if _has_commit(repo, "HEAD~1"):
            files = _diff_filenames(repo, "HEAD~1...HEAD")
            diff = _diff_text(repo, "HEAD~1...HEAD")
            return DiffResult("HEAD~1", "HEAD", files, diff, changed_line_ranges=parse_changed_line_ranges(diff))
        files = _diff_filenames(repo, None)
        diff = _diff_text(repo, None)
        return DiffResult(None, "HEAD", files, diff, fallback_used=True, changed_line_ranges=parse_changed_line_ranges(diff))
    except ToolNotFoundError:
        log.warning("git not installed; falling back to file walk")
        return DiffResult(None, None, _walk_files(repo), "", fallback_used=True)


# ---------------------------------------------------------------------- helpers


def _has_commit(repo: str, ref: str) -> bool:
    r = run(["git", "rev-parse", "--verify", ref], cwd=repo, timeout=10)
    return r.ok


def _diff_filenames(repo: str, range_: str | None) -> list[str]:
    cmd = ["git", "diff", "--name-only"]
    if range_:
        cmd.append(range_)
    r = run(cmd, cwd=repo, timeout=30)
    if not r.ok:
        # Loud when git rejects the range (e.g. a ref that doesn't exist
        # locally). Previously this silently returned [] and the whole
        # pipeline thought the PR had no changes — a false negative.
        log.warning(
            "git diff --name-only %s failed: %s",
            range_ or "<no-range>", (r.stderr or r.stdout or "").strip()[:200],
        )
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def _diff_text(repo: str, range_: str | None) -> str:
    cmd = ["git", "diff", "--unified=3"]
    if range_:
        cmd.append(range_)
    r = run(cmd, cwd=repo, timeout=60)
    if not r.ok:
        log.warning(
            "git diff %s failed: %s",
            range_ or "<no-range>", (r.stderr or r.stdout or "").strip()[:200],
        )
        return ""
    return r.stdout


_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_FILE_HEADER_RE = re.compile(r"^\+\+\+ (?:b/)?(.+)$")


def parse_changed_line_ranges(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Extract added/modified line ranges per file from a unified diff.

    Reads `+++ b/<file>` headers to anchor the current file and `@@ -... +N,M @@`
    hunk headers to recover the *new-file* line span. Returns a dict mapping
    forward-slash repo-relative paths to a list of `(start, end_inclusive)`
    tuples. A file with no changes (only context/removal hunks where M=0)
    contributes no ranges.

    Pure string parsing — no `git` invocation — so it works on any diff
    obtained however (including the one we already capture in DiffResult).
    """
    ranges: dict[str, list[tuple[int, int]]] = {}
    current_file: str | None = None
    for line in (diff_text or "").splitlines():
        m_file = _FILE_HEADER_RE.match(line)
        if m_file:
            path = m_file.group(1).strip()
            # `/dev/null` appears for deletions — skip; nothing to scan there.
            current_file = None if path == "/dev/null" else path.replace("\\", "/")
            continue
        if current_file is None:
            continue
        m_hunk = _HUNK_HEADER_RE.match(line)
        if not m_hunk:
            continue
        start = int(m_hunk.group(1))
        count_str = m_hunk.group(2)
        count = int(count_str) if count_str is not None else 1
        if count <= 0:
            # Pure deletion hunk — no new-file lines to track.
            continue
        end = start + count - 1
        ranges.setdefault(current_file, []).append((start, end))
    return ranges


def _walk_files(repo: str) -> list[str]:
    """When git is unavailable or there are no commits, list files manually."""
    skip_dirs = {
        ".git", ".venv", "venv", "__pycache__", "node_modules", ".secureflow_cache",
        "dist", "build", ".idea", ".vscode",
    }
    out: list[str] = []
    root = Path(repo)
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        # Skip hidden trees + known noise
        if any(part in skip_dirs or part.startswith(".") for part in p.relative_to(root).parts[:-1]):
            continue
        out.append(str(p.relative_to(root)).replace("\\", "/"))
    return sorted(out)
