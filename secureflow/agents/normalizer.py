"""Finding normalizer.

Merges the four scanner streams into one list, de-duplicates, and sorts
deterministically. Two layers of de-dup:

1. **By stable ID** — catches genuine duplicates where two streams produced
   exactly the same finding (e.g. semgrep + bandit on the same Python rule).
2. **By co-location** — collapses near-duplicate findings from the same
   scanner where multiple rules fire on the same source line (e.g. semgrep
   `auto` config emits Django + generic + Flask + SQLAlchemy variants of
   the same SQLi). The highest-severity finding wins; the dropped rules are
   recorded on its `extra_rule_ids` field for traceability.

This dramatically reduces LLM token spend in the exploitability node and
keeps the report focused on distinct issues, not scanner variants.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from secureflow.schemas.finding import Finding
from secureflow.utils.logging import get_logger

log = get_logger("agent.normalizer")


def _normalize_path(raw: str, repo_root: Path) -> str:
    """Convert a finding's file_path to a repo-relative POSIX path.

    Scanners produce a mix of absolute paths (semgrep on a tmp checkout
    often does this) and repo-relative paths. `git diff --name-only`
    always emits repo-relative POSIX paths. Normalize both sides to
    repo-relative POSIX so set membership works on Windows too.
    """
    p = Path(raw)
    try:
        return p.resolve().relative_to(repo_root).as_posix()
    except (ValueError, OSError):
        # Already relative or outside repo — fall back to as-posix.
        return p.as_posix().lstrip("./")


# ─────────────────────────────────────────── deterministic confidence floor ──
# When a SAST finding's surrounding code visibly contains a tainted input
# source (request param, query string, form data, env input, raw request
# body, etc.) AND the finding's rule_id matches a known sink family, we
# floor confidence at FLOOR. This protects the decision against under-rated
# semgrep findings on cross-language code (the live xlang eval showed
# medium-impact rules at confidence 0.40, so the policy didn't even WARN)
# without depending on the LLM being available.

_SAST_SOURCES = frozenset({"semgrep", "bandit", "sast"})

_TAINT_SOURCES_RE = re.compile(
    # Python
    r"\brequest\.(args|form|values|json|cookies|headers|GET|POST)\b"
    r"|\bflask\.request\b|\bdjango\.request\b"
    # JS / TS Node
    r"|\breq\.(query|body|params|cookies|headers)\b"
    r"|\brequest\.(query|body|params|cookies|headers)\b"
    # Go
    r"|\br\.URL\.Query\(\s*\)"
    r"|\br\.(PostForm|FormValue|PostFormValue|Form|Header)\b"
    r"|\bmux\.Vars\s*\(\s*r\s*\)"
    r"|\bc\.(Query|PostForm|Param|FormValue|GetHeader)\s*\("
    # Java
    r"|\b(request|req)\.getParameter\s*\("
    r"|\b(request|req)\.getQueryString\s*\("
    r"|@RequestParam\b|@PathVariable\b|@RequestBody\b"
    # Ruby
    r"|\bparams\s*\["
    r"|\brequest\.params\b"
    # PHP
    r"|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"
    r"|\$request->(?:input|query|all|file)\s*\("
    # C#
    r"|\bRequest\.(QueryString|Form|Params|Cookies|Headers)\b"
    r"|\bHttpContext\.Request\b",
)

# Rule-id substrings that identify the finding as a sink whose risk is
# meaningfully elevated when paired with a tainted input on the surrounding
# lines. Lower-cased substring match against rule_id.
_KNOWN_SINK_RULE_SUBSTRINGS = (
    "sqli", "sql-injection", "sql_injection", "tainted-sql-string",
    "string-formatted-query", "formatted-sql-string",
    "command-injection", "shell-injection", "dangerous-subshell",
    "dangerous-spawn-shell", "dangerous-exec", "detect-child-process",
    "path-traversal", "directory-traversal",
    "xxe", "documentbuilderfactory-disallow-doctype", "external-entity",
    "ssrf", "server-side-request-forgery",
    "raw-html-format", "raw-html",  # XSS sinks
    "open-redirect", "unsafe-redirect",
    "deserialization", "pickle", "unsafe-yaml",
)

_SEVERITY_ORDER_FOR_FLOOR = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_FLOOR_CONFIDENCE = 0.7
_TAINT_CONTEXT_LINES = 8


def _has_taint_nearby(finding: dict, repo_root: Path) -> bool:
    """Read lines around the finding and check for a taint-source pattern."""
    fp = finding.get("file_path")
    line = finding.get("start_line")
    if not fp or not line:
        return False
    p = Path(fp)
    if not p.is_absolute():
        p = repo_root / fp
    if not p.exists() or not p.is_file():
        return False
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    lines = text.splitlines()
    lo = max(0, int(line) - 1 - _TAINT_CONTEXT_LINES)
    hi = min(len(lines), int(line) + _TAINT_CONTEXT_LINES)
    return bool(_TAINT_SOURCES_RE.search("\n".join(lines[lo:hi])))


def _is_known_sink_rule(rule_id: str | None) -> bool:
    if not rule_id:
        return False
    low = rule_id.lower()
    return any(s in low for s in _KNOWN_SINK_RULE_SUBSTRINGS)


def _apply_taint_floor(findings: list[dict], pr_context: dict) -> tuple[list[dict], int]:
    """Floor confidence at 0.7 on SAST findings where a tainted input is
    visible near the sink AND the rule is a known sink family. Mutates each
    affected finding's `confidence` in place.

    No extra metadata fields are written onto the finding dict because the
    Finding pydantic schema declares `extra="ignore"` — any non-schema key
    would be lost on the next model_validate() downstream. We log the
    decision instead so audit-ability is in the structured log stream.
    """
    repo_root = Path(pr_context.get("repo_path") or ".").resolve()
    floored = 0
    for f in findings:
        if (f.get("source") or "").lower() not in _SAST_SOURCES:
            continue
        sev = (f.get("severity") or "medium").lower()
        if _SEVERITY_ORDER_FOR_FLOOR.get(sev, 0) < _SEVERITY_ORDER_FOR_FLOOR["medium"]:
            continue
        prev = float(f.get("confidence") or 0.0)
        if prev >= _FLOOR_CONFIDENCE:
            continue
        if not _is_known_sink_rule(f.get("rule_id")):
            continue
        if not _has_taint_nearby(f, repo_root):
            continue
        f["confidence"] = _FLOOR_CONFIDENCE
        floored += 1
        log.info(
            "confidence floored",
            extra={
                "finding_id": f.get("id"),
                "rule_id": f.get("rule_id"),
                "file": f.get("file_path"),
                "line": f.get("start_line"),
                "from": prev,
                "to": _FLOOR_CONFIDENCE,
            },
        )
    return findings, floored


# Scanner sources we will line-filter against the PR diff. Gitleaks and
# Grype findings stay file-scoped because a secret committed earlier in
# an untouched line is still leaked, and a vulnerable dependency does
# not have a meaningful line number. AI Discovery is already PR-aware on
# its own (it's prompted with the diff); double-filtering it here would
# silently drop legitimate findings whose line cite is off by one.
_LINE_FILTER_SOURCES = frozenset({"semgrep", "bandit", "sast"})


def _restrict_to_pr_diff_lines(
    findings: list[dict],
    pr_context: dict,
    *,
    tolerance: int = 2,
) -> tuple[list[dict], int]:
    """Drop SAST findings whose line is outside the PR's changed line ranges.

    File-level scoping (above) removes findings in files the PR didn't
    touch. This second pass removes findings in *lines* the PR didn't
    touch within files it did. On real PRs this is a big noise reduction:
    semgrep auto-config commonly flags pre-existing issues in a touched
    file, and those are not this PR's responsibility.

    - Findings from sources not in `_LINE_FILTER_SOURCES` pass through.
    - Findings without a `start_line` pass through (no anchor to filter on).
    - If a file appears in `changed_files` but has no recorded line ranges
      (e.g. binary diff, or no diff text captured), we KEEP all findings
      in that file rather than dropping them — silent over-drop is the
      worse failure mode here.
    - `tolerance` lets a finding cited a couple lines off (semgrep reports
      the rule's anchor, which can be a few lines above the actual sink)
      still count as in-range.
    """
    changed_ranges_raw = pr_context.get("changed_line_ranges") or []
    if not changed_ranges_raw:
        return findings, 0

    repo_root = Path(pr_context.get("repo_path") or ".").resolve()
    ranges_by_file: dict[str, list[tuple[int, int]]] = {}
    for r in changed_ranges_raw:
        path = _normalize_path(r.get("file") or "", repo_root)
        start = int(r.get("start") or 0)
        end = int(r.get("end") or start)
        if not path or start <= 0:
            continue
        ranges_by_file.setdefault(path, []).append((start, end))

    if not ranges_by_file:
        return findings, 0

    kept: list[dict] = []
    dropped = 0
    for f in findings:
        src = (f.get("source") or "").lower()
        if src not in _LINE_FILTER_SOURCES:
            kept.append(f)
            continue
        fp = f.get("file_path")
        line = f.get("start_line")
        if not fp or not line:
            kept.append(f)
            continue
        norm = _normalize_path(fp, repo_root)
        ranges = ranges_by_file.get(norm)
        if not ranges:
            # File touched but no line-range info — keep, don't silently drop.
            kept.append(f)
            continue
        fend = f.get("end_line") or line
        if _line_in_any_range(int(line), int(fend), ranges, tolerance):
            kept.append(f)
        else:
            dropped += 1
    return kept, dropped


def _line_in_any_range(
    start: int, end: int, ranges: list[tuple[int, int]], tolerance: int
) -> bool:
    """True iff [start, end] overlaps any (s, e) range with `tolerance` slack."""
    for s, e in ranges:
        if not (end < s - tolerance or start > e + tolerance):
            return True
    return False


def _restrict_to_pr_diff(
    findings: list[dict],
    pr_context: dict,
) -> tuple[list[dict], int]:
    """Drop findings whose file_path isn't in `pr_context.changed_files`.

    Without this, a PR-review run on a real repo reports findings on EVERY
    file in the checkout — including pre-existing issues that aren't the
    PR's responsibility. The PR comment becomes a wall of noise and the
    `FAIL` decision misattributes blame to the PR author.

    Behaviour:
    - If `changed_files` is empty (no diff context, e.g. local non-git
      walk), apply no filter — the caller wanted everything.
    - Findings without a `file_path` (e.g. dependency CVEs without a
      physical location) are kept regardless.
    - Path comparison is repo-relative POSIX, so absolute paths from
      semgrep and Windows backslashes from grype both work.
    """
    changed: list[str] = pr_context.get("changed_files") or []
    if not changed:
        return findings, 0

    repo_root = Path(pr_context.get("repo_path") or ".").resolve()
    changed_set = {_normalize_path(p, repo_root) for p in changed}

    kept: list[dict] = []
    dropped = 0
    for f in findings:
        fp = f.get("file_path")
        if not fp:
            kept.append(f)
            continue
        if _normalize_path(fp, repo_root) in changed_set:
            kept.append(f)
        else:
            dropped += 1
    return kept, dropped


def normalize(state: dict) -> dict:
    streams: list[tuple[str, Iterable[dict]]] = [
        ("secret_findings", state.get("secret_findings") or []),
        ("sast_findings", state.get("sast_findings") or []),
        ("dependency_findings", state.get("dependency_findings") or []),
        ("iac_findings", state.get("iac_findings") or []),
        ("ai_discovery_findings", state.get("ai_discovery_findings") or []),
    ]

    by_id: dict[str, dict] = {}
    invalid = 0
    for _, items in streams:
        for item in items:
            try:
                f = Finding.model_validate(item)
            except Exception as e:
                invalid += 1
                log.warning("dropping invalid finding: %s", e)
                continue
            existing = by_id.get(f.id)
            if existing is None:
                by_id[f.id] = f.model_dump()
            else:
                if _priority(f.source) > _priority(existing.get("source", "")):
                    by_id[f.id] = f.model_dump()

    collapsed, collapsed_count = _collapse_colocated(list(by_id.values()))

    # Restrict to files actually touched by the PR. Without this filter,
    # scanners that walk the full repo (semgrep, gitleaks, grype on a
    # checkout) flag pre-existing issues that aren't the PR's fault.
    pr_context = state.get("pr_context") or {}
    in_scope, dropped_out_of_scope = _restrict_to_pr_diff(collapsed, pr_context)
    # Second pass: drop SAST findings whose line is outside the PR's
    # changed-line ranges within the touched files. Gitleaks/Grype/AI
    # findings pass through (see _LINE_FILTER_SOURCES rationale).
    in_scope, dropped_off_diff_lines = _restrict_to_pr_diff_lines(in_scope, pr_context)

    # Deterministic confidence floor for clearly-tainted SAST findings.
    # Runs before exploitability so the LLM has accurate confidence as
    # input — and so the decision is right even when the LLM is down.
    in_scope, floored_count = _apply_taint_floor(in_scope, pr_context)

    normalized = sorted(
        in_scope,
        key=lambda x: (
            x.get("file_path") or "",
            x.get("start_line") or 0,
            x.get("source") or "",
        ),
    )
    log.info(
        "normalized %d findings (collapsed %d co-located variants, "
        "%d invalid dropped, %d out-of-scope dropped, %d off-diff-line SAST "
        "dropped, %d confidence-floored)",
        len(normalized), collapsed_count, invalid, dropped_out_of_scope,
        dropped_off_diff_lines, floored_count,
    )
    return {"normalized_findings": normalized}


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _collapse_colocated(findings: list[dict]) -> tuple[list[dict], int]:
    """Merge same-scanner findings that share (file, line range).

    Skips gitleaks (each secret is genuinely distinct even on the same line).
    Skips findings without a file_path (e.g., dependency CVEs without a
    physical location).
    """
    keep: list[dict] = []
    grouped: dict[tuple, list[dict]] = {}

    for f in findings:
        src = f.get("source")
        path = f.get("file_path")
        start = f.get("start_line")
        end = f.get("end_line") or start
        # Findings we never collapse — they're either inherently distinct
        # (gitleaks: every secret is its own finding) or lack the location
        # data we'd group on.
        if src == "gitleaks" or not path or start is None:
            keep.append(f)
            continue
        key = (src, path, start, end)
        grouped.setdefault(key, []).append(f)

    collapsed_count = 0
    for (_src, _path, _start, _end), group in grouped.items():
        if len(group) == 1:
            keep.append(group[0])
            continue
        # Pick the highest-severity, highest-confidence finding as the
        # primary. Roll the other rule IDs onto it as evidence so the report
        # can show what else fired without exploding finding count.
        group.sort(
            key=lambda x: (
                _SEVERITY_ORDER.get(x.get("severity", "info"), 0),
                float(x.get("confidence") or 0.0),
            ),
            reverse=True,
        )
        primary = dict(group[0])
        extra_rule_ids = sorted({
            x.get("rule_id") for x in group[1:] if x.get("rule_id")
        })
        if extra_rule_ids:
            note = "Also flagged by: " + ", ".join(extra_rule_ids)
            existing_desc = primary.get("description") or ""
            primary["description"] = (
                f"{existing_desc}\n\n{note}" if existing_desc else note
            )
        keep.append(primary)
        collapsed_count += len(group) - 1

    return keep, collapsed_count


_SOURCE_PRIORITY = {
    "gitleaks": 5,
    "grype": 4,
    "osv": 4,
    # Checkov is deterministic and rule-based on IaC frames; treat it on
    # par with the other deterministic scanners. Wins over ai_discovery
    # on the same finding because Checkov's policy IDs are stable and
    # well-documented while LLM dedup-keys can drift on rephrasing.
    "checkov": 3,
    "semgrep": 3,
    "bandit": 3,
    "ai_discovery": 2,
    "manual": 1,
}


def _priority(source: str) -> int | float:
    return _SOURCE_PRIORITY.get(source, 0)
