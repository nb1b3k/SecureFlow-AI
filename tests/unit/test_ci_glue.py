"""Unit tests for CI-only code paths that only fire under GITHUB_ACTIONS=true.

These are the glue layers around the GitHub Actions workflow:
  - `secureflow.cli._post_pr_comment_if_possible` — reads env vars + event
    payload, decides whether to call the PR-comment API.
  - `secureflow.agents.context_agent._load_github_event_metadata` — parses
    the pull_request event JSON into a PRContext.
  - `secureflow.tools.git_diff._refs_from_env` / `compute_diff` — picks the
    right base/head refs from CI env vars, falls back gracefully when git
    rejects the range (was a silent false-negative bug before).

All tests are offline: env vars are monkey-patched, the event payload is
a tmp file, GitHub HTTP is mocked, and git is invoked against a tmp repo.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from secureflow.agents.context_agent import _load_github_event_metadata
from secureflow.cli import _post_pr_comment_if_possible
from secureflow.tools.git_diff import _refs_from_env, compute_diff

# ─────────────────────────────────────────── _post_pr_comment_if_possible ──


def test_post_pr_skip_when_not_in_github_actions(monkeypatch) -> None:
    """No GITHUB_ACTIONS=true → silent no-op (local `scan-pr` should not post)."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    called = []
    with patch(
        "secureflow.tools.github_api.post_or_update_comment",
        side_effect=lambda **kw: called.append(kw),
    ):
        _post_pr_comment_if_possible("body")
    assert called == []


def test_post_pr_skip_when_missing_repo_or_event_path(monkeypatch) -> None:
    """GITHUB_ACTIONS=true but no repo/event path → also no-op."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    called = []
    with patch(
        "secureflow.tools.github_api.post_or_update_comment",
        side_effect=lambda **kw: called.append(kw),
    ):
        _post_pr_comment_if_possible("body")
    assert called == []


def test_post_pr_skip_when_event_payload_malformed(monkeypatch, tmp_path) -> None:
    """Malformed event JSON should not crash; just skip the post."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    event_path = tmp_path / "event.json"
    event_path.write_text("not json {", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    called = []
    with patch(
        "secureflow.tools.github_api.post_or_update_comment",
        side_effect=lambda **kw: called.append(kw),
    ):
        _post_pr_comment_if_possible("body")
    assert called == []


def test_post_pr_skip_when_event_has_no_pull_request(monkeypatch, tmp_path) -> None:
    """Push event payload (no pull_request key) → skip."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"action": "push"}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    called = []
    with patch(
        "secureflow.tools.github_api.post_or_update_comment",
        side_effect=lambda **kw: called.append(kw),
    ):
        _post_pr_comment_if_possible("body")
    assert called == []


def test_post_pr_calls_api_on_happy_path(monkeypatch, tmp_path) -> None:
    """All env vars set + valid pull_request event → call post_or_update_comment."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps({"pull_request": {"number": 42}}), encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    called: list[dict] = []
    with patch(
        "secureflow.tools.github_api.post_or_update_comment",
        side_effect=lambda **kw: called.append(kw),
    ):
        _post_pr_comment_if_possible("**body**")
    assert len(called) == 1
    assert called[0]["repo"] == "owner/repo"
    assert called[0]["pr_number"] == 42
    assert called[0]["body"] == "**body**"


# ─────────────────────────────────────── _load_github_event_metadata ──


def test_event_metadata_empty_outside_actions(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    meta = _load_github_event_metadata()
    assert meta.repo_name is None
    assert meta.pr_number is None


def test_event_metadata_parses_pr_payload(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({
        "pull_request": {
            "number": 99,
            "base": {"ref": "main"},
            "head": {"ref": "feature/x"},
        },
    }), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    meta = _load_github_event_metadata()
    assert meta.repo_name == "owner/repo"
    assert meta.pr_number == 99
    assert meta.base_branch == "main"
    assert meta.head_branch == "feature/x"


def test_event_metadata_handles_malformed_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    event_path = tmp_path / "event.json"
    event_path.write_text("not-json", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    meta = _load_github_event_metadata()
    # repo_name still picked up from env, but pr_number is None.
    assert meta.repo_name == "owner/repo"
    assert meta.pr_number is None


# ────────────────────────────────────────────── git_diff CI behavior ──


def test_refs_from_env_outside_actions(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert _refs_from_env() == (None, None)


def test_refs_from_env_pr_event_uses_HEAD_as_head(monkeypatch) -> None:
    """pull_request event: base is `origin/<branch>`, head is `HEAD`.

    This is the fix for the silent-false-negative bug — `actions/checkout`
    leaves the working tree detached at the merge commit, so `HEAD` is the
    only ref we can reliably name for the head side.
    """
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/sqli")
    monkeypatch.setenv("GITHUB_SHA", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    base, head = _refs_from_env()
    assert base == "origin/main"
    assert head == "HEAD"


def test_refs_from_env_already_prefixed_base_kept_as_is(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_BASE_REF", "origin/develop")
    monkeypatch.setenv("GITHUB_HEAD_REF", "topic")
    base, head = _refs_from_env()
    assert base == "origin/develop"
    assert head == "HEAD"


def test_refs_from_env_push_event_uses_sha(monkeypatch) -> None:
    """Push event has no GITHUB_BASE_REF — fall back to GITHUB_SHA as head, no base."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_HEAD_REF", raising=False)
    monkeypatch.setenv("GITHUB_SHA", "cafebabecafebabecafebabecafebabecafebabe")
    base, head = _refs_from_env()
    assert base is None
    assert head == "cafebabecafebabecafebabecafebabecafebabe"


# ───────────────────────────────────────── compute_diff CI integration ──


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _make_pr_like_repo(workdir: Path) -> None:
    """Build a tmp repo with a base commit + a PR commit, detached HEAD.

    Mimics what actions/checkout@v4 leaves on a pull_request event:
    `origin/main` is fetched, HEAD is a commit on the (now-deleted) feature
    branch. `feature/sqli` is NOT resolvable as a local ref.
    """
    _git(["init", "-q", "-b", "main"], workdir)
    _git(["config", "user.email", "test@example.com"], workdir)
    _git(["config", "user.name", "Test"], workdir)
    (workdir / "a.py").write_text("print('base')\n", encoding="utf-8")
    _git(["add", "."], workdir)
    _git(["commit", "-q", "-m", "base"], workdir)
    base_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=workdir, capture_output=True, text=True, check=True,
    ).stdout.strip()
    _git(["update-ref", "refs/remotes/origin/main", base_sha], workdir)

    _git(["checkout", "-q", "-b", "feature/sqli"], workdir)
    (workdir / "a.py").write_text("print('pr change')\n", encoding="utf-8")
    _git(["add", "."], workdir)
    _git(["commit", "-q", "-m", "pr"], workdir)
    # Detach + delete the local branch — that's what real CI looks like.
    _git(["checkout", "-q", "--detach", "HEAD"], workdir)
    _git(["branch", "-q", "-D", "feature/sqli"], workdir)


def test_compute_diff_under_ci_detects_pr_changes(monkeypatch, tmp_path) -> None:
    """End-to-end: a realistic detached-HEAD repo + CI env vars yields the
    expected one-file diff. This is the regression test for the silent
    false-negative bug fixed in git_diff.py."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_pr_like_repo(repo)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/sqli")
    monkeypatch.delenv("GITHUB_SHA", raising=False)

    result = compute_diff(str(repo))
    assert result.changed_files == ["a.py"], result
    assert "pr change" in result.diff_text
    assert result.base_ref == "origin/main"
    assert result.head_ref == "HEAD"


def test_compute_diff_under_ci_warns_on_bad_range(monkeypatch, tmp_path, caplog) -> None:
    """Engineered failure: the base ref doesn't exist. Old behavior: silent
    empty diff. New behavior: log a warning AND still return empty so the
    pipeline keeps moving (just without diff context)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_pr_like_repo(repo)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    # Bogus base — origin/nope doesn't exist locally.
    monkeypatch.setenv("GITHUB_BASE_REF", "nope")

    with caplog.at_level("WARNING", logger="secureflow.git"):
        result = compute_diff(str(repo))
    assert result.changed_files == []
    # Loud warning so the pipeline-level operator can see "the diff was
    # empty because git rejected the range", not "the PR has no changes".
    msgs = " | ".join(r.getMessage() for r in caplog.records)
    assert "git diff" in msgs
