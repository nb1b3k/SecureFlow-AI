"""Build the `PRContext` for downstream agents.

v1 covers:
- Changed-file enumeration via git (or whole-tree fallback).
- Language summary by extension.
- Sensitive-file detection via `analysis.ast_signals.detect_path`.

Function-boundary extraction (design/05 / design/06) is left as a v2
enhancement — currently we pass empty `function_boundaries`. The orchestrator
and AI Discovery agent handle that gracefully.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from secureflow.analysis import ast_signals
from secureflow.analysis.path_rules import language_of
from secureflow.config import Config
from secureflow.schemas.pr_context import ChangedLineRange, PRContext
from secureflow.tools.git_diff import compute_diff
from secureflow.utils.logging import get_logger

log = get_logger("agent.context")


@dataclass
class _GhPrMeta:
    """PR metadata pulled from GITHUB_EVENT_PATH when running in Actions."""
    repo_name: str | None = None
    pr_number: int | None = None
    base_branch: str | None = None
    head_branch: str | None = None


def _load_github_event_metadata() -> _GhPrMeta:
    """Best-effort parse of the GitHub event payload.

    GitHub Actions writes the triggering event's JSON to a file pointed to
    by `GITHUB_EVENT_PATH`. On `pull_request` events this contains the PR
    number, head/base ref names, and repo full name. Outside Actions we
    return an empty record and the rest of the pipeline degrades gracefully.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return _GhPrMeta()

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo_full = os.environ.get("GITHUB_REPOSITORY") or None
    if not event_path:
        return _GhPrMeta(repo_name=repo_full)

    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("could not parse GITHUB_EVENT_PATH: %s", e)
        return _GhPrMeta(repo_name=repo_full)

    pr = event.get("pull_request") or {}
    pr_number = pr.get("number")
    base_branch = (pr.get("base") or {}).get("ref")
    head_branch = (pr.get("head") or {}).get("ref")

    return _GhPrMeta(
        repo_name=repo_full,
        pr_number=int(pr_number) if isinstance(pr_number, int) else None,
        base_branch=base_branch,
        head_branch=head_branch,
    )


def collect_context(state: dict) -> dict:
    """LangGraph node: build `pr_context` from `config`."""
    cfg = Config.model_validate(state.get("config") or {})
    repo_path = state.get("repo_path") or "."

    diff = compute_diff(repo_path)
    changed_files = diff.changed_files

    # Language distribution by extension
    lang_counts: Counter[str] = Counter()
    for f in changed_files:
        lang = language_of(f) or "unknown"
        lang_counts[lang] += 1

    # Sensitive detection — check each changed file
    sensitive_signals: set[str] = set()
    for f in changed_files:
        res = ast_signals.detect_path(
            repo_path, f,
            sensitive_path_patterns=cfg.ai_discovery.sensitive_patterns,
            exclusion_paths=cfg.ai_discovery.exclusion_paths,
        )
        if res.sensitive:
            for s in res.signals:
                sensitive_signals.add(s)

    # GitHub Actions PR metadata (no-op outside Actions).
    gh = _load_github_event_metadata()

    changed_line_ranges = [
        ChangedLineRange(file=fpath, start=start, end=end)
        for fpath, ranges in (diff.changed_line_ranges or {}).items()
        for start, end in ranges
    ]

    pr_context = PRContext(
        repo_path=str(repo_path),
        repo_name=gh.repo_name,
        pr_number=gh.pr_number,
        # GH event ref names are nicer than `origin/<branch>` from git_diff;
        # prefer them when present, but fall back to the diff agent's view.
        base_branch=gh.base_branch or diff.base_ref,
        head_branch=gh.head_branch or diff.head_ref,
        changed_files=changed_files,
        changed_line_ranges=changed_line_ranges,
        diff=diff.diff_text,
        language_summary=dict(lang_counts),
        sensitive_files_changed=bool(sensitive_signals),
        sensitive_signals=sorted(sensitive_signals),
    )
    log.info(
        "context built",
        extra={
            "changed_files": len(changed_files),
            "languages": dict(lang_counts),
            "sensitive": pr_context.sensitive_files_changed,
            "pr_number": pr_context.pr_number,
            "repo": pr_context.repo_name,
        },
    )
    return {"pr_context": pr_context.model_dump()}
