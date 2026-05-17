"""Temp git worktree management for patch validation.

A `TempWorktree` is a throwaway checkout of the same git repository at a
different path. Applying a candidate patch there and re-running the
originating scanner gives us a high-confidence verification signal
("the scanner no longer flags this issue") without touching the user's
working tree.

When the host repo isn't a git repo (e.g. fixture directories or ad-hoc
scans), we fall back to a plain directory copy. The patch is then applied
with `git apply --no-index`, which still works on non-git trees.

See `design/03_patch_validation.md` for the full design.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from types import TracebackType

from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import ToolNotFoundError, run

log = get_logger("patch_loop")


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


class TempWorktree:
    """Throwaway working copy of `repo_path`, cleaned up on context exit."""

    def __init__(self, repo_path: str | Path) -> None:
        self.source = Path(repo_path).resolve()
        self.path: Path | None = None
        self._is_git = False
        self._cleanup_mode: str = "copy"  # one of: "git_worktree", "copy"

    # ─────────────────────────────────────────────────────────── context ──

    def __enter__(self) -> TempWorktree:
        self.path = Path(tempfile.mkdtemp(prefix="secureflow-patch-"))
        try:
            if _is_git_repo(self.source):
                # `git worktree add --detach` is fast (~100ms) and shares the
                # object database with the source repo.
                proc = run(
                    [
                        "git", "worktree", "add", "--detach",
                        str(self.path), "HEAD",
                    ],
                    cwd=str(self.source),
                    timeout=30,
                )
                if proc.ok:
                    self._is_git = True
                    self._cleanup_mode = "git_worktree"
                    log.debug(
                        "git worktree created", extra={"path": str(self.path)},
                    )
                else:
                    log.warning(
                        "git worktree add failed (%s); falling back to copy",
                        proc.stderr[:200],
                    )
                    self._copy_tree()
            else:
                self._copy_tree()
        except (ToolNotFoundError, OSError) as e:
            log.warning("git worktree unavailable (%s); using directory copy", e)
            self._copy_tree()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.path is None:
            return
        try:
            if self._cleanup_mode == "git_worktree":
                run(
                    ["git", "worktree", "remove", "--force", str(self.path)],
                    cwd=str(self.source),
                    timeout=15,
                )
        except Exception as e:  # pragma: no cover - cleanup best-effort
            log.debug("git worktree remove failed: %s", e)
        # Always try filesystem cleanup as a backstop.
        shutil.rmtree(self.path, ignore_errors=True)
        self.path = None

    # ─────────────────────────────────────────────────────────── helpers ──

    def _copy_tree(self) -> None:
        assert self.path is not None
        # Empty the temp dir and re-populate from the source.
        if self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        shutil.copytree(
            self.source,
            self.path,
            ignore=shutil.ignore_patterns(
                ".git", ".venv", "venv", "node_modules", ".secureflow_cache",
                "__pycache__", ".pytest_cache", "dist", "build", "reports",
            ),
        )
        self._is_git = False
        self._cleanup_mode = "copy"

    def apply_patch(self, unified_diff: str) -> bool:
        """Apply a unified-diff patch to the worktree. Returns True on success."""
        if not unified_diff or self.path is None:
            return False
        # `git apply` works both inside a git worktree and on a plain dir
        # (with --no-index). We use --reject=false (default) so partial
        # applies don't leave .rej files behind.
        cmd = ["git", "apply", "--whitespace=nowarn"]
        if not self._is_git:
            cmd.append("--no-index")
        # Encode the diff as UTF-8 BYTES before handing to subprocess. With
        # `text=True` and a str payload, Python translates `\n` -> os.linesep
        # on Windows, which corrupts the patch (the diff's LF lines no
        # longer match the LF-newlined source file, and `git apply` fails
        # with "patch does not apply"). Sending bytes bypasses translation.
        diff_text = unified_diff if unified_diff.endswith("\n") else unified_diff + "\n"
        diff_bytes = diff_text.encode("utf-8")
        try:
            proc = run(
                cmd,
                cwd=str(self.path),
                input_data=diff_bytes,
                timeout=15,
            )
        except ToolNotFoundError:
            log.warning("git not installed; can't apply patch")
            return False
        if not proc.ok:
            log.info(
                "git apply rejected patch",
                extra={"stderr_head": proc.stderr[:200]},
            )
        return proc.ok

    def read(self, relative_path: str) -> str:
        """Read a file from the worktree."""
        assert self.path is not None
        return (self.path / relative_path).read_text(encoding="utf-8", errors="replace")

    @property
    def root(self) -> str:
        assert self.path is not None
        return str(self.path)


def prune_stale_worktrees(repo_path: str | Path) -> None:
    """Run `git worktree prune` to clean up after crashed prior runs.

    Idempotent and safe to call at orchestrator startup.
    """
    p = Path(repo_path)
    if not _is_git_repo(p):
        return
    try:
        run(["git", "worktree", "prune"], cwd=str(p), timeout=10)
    except ToolNotFoundError:
        pass
