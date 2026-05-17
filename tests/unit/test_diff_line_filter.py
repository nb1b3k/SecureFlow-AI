"""Unit tests for diff-line scoping.

Covers:
1. `parse_changed_line_ranges` — extracts per-file `+start,count` hunks
   from a unified diff, ignores pure-deletion hunks, skips `/dev/null`.
2. `_restrict_to_pr_diff_lines` — keeps SAST findings inside changed
   ranges, drops SAST findings outside, leaves gitleaks/grype/AI alone.

Both functions are pure (no git invocation, no filesystem), so the tests
exercise their string-and-dict inputs directly.
"""

from __future__ import annotations

from secureflow.agents.normalizer import _restrict_to_pr_diff_lines
from secureflow.tools.git_diff import parse_changed_line_ranges

_SAMPLE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -10,3 +10,5 @@ def existing():
     return 1

+def newly_added(uid):
+    return db.execute("SELECT * FROM u WHERE id=" + uid)
+
diff --git a/utils.py b/utils.py
index 3333333..4444444 100644
--- a/utils.py
+++ b/utils.py
@@ -42,5 +42,5 @@ class Helper:
     def a(self): pass
-    def b(self): return 1
+    def b(self): return 2
     def c(self): pass
diff --git a/removed.py b/removed.py
deleted file mode 100644
index 5555555..0000000
--- a/removed.py
+++ /dev/null
@@ -1,5 +0,0 @@
-line1
-line2
"""


def test_parse_changed_line_ranges_extracts_per_file_ranges() -> None:
    ranges = parse_changed_line_ranges(_SAMPLE_DIFF)

    # app.py: hunk header `@@ -10,3 +10,5 @@` -> new file lines 10..14
    assert ranges["app.py"] == [(10, 14)]
    # utils.py: `@@ -42,5 +42,5 @@` -> new file lines 42..46
    assert ranges["utils.py"] == [(42, 46)]
    # removed.py target is /dev/null — not tracked
    assert "removed.py" not in ranges


def test_parse_changed_line_ranges_handles_single_line_hunk() -> None:
    diff = (
        "+++ b/single.py\n"
        "@@ -5 +5 @@\n"
        "-old\n"
        "+new\n"
    )
    ranges = parse_changed_line_ranges(diff)
    # Missing count means count=1 by the unified-diff spec.
    assert ranges == {"single.py": [(5, 5)]}


def test_parse_changed_line_ranges_skips_pure_deletion_hunks() -> None:
    diff = (
        "+++ b/foo.py\n"
        "@@ -10,3 +10,0 @@\n"
        "-line1\n"
        "-line2\n"
        "-line3\n"
    )
    # New-side count is 0 — nothing to track.
    assert parse_changed_line_ranges(diff) == {}


def test_parse_changed_line_ranges_empty_input() -> None:
    assert parse_changed_line_ranges("") == {}
    assert parse_changed_line_ranges(None) == {}  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────── filter tests ──


def _ctx(repo: str, ranges: list[dict]) -> dict:
    return {"repo_path": repo, "changed_line_ranges": ranges}


def _f(source: str, file_path: str, line: int, **extra) -> dict:
    return {"source": source, "file_path": file_path, "start_line": line, **extra}


def test_filter_keeps_sast_inside_range(tmp_path) -> None:
    ctx = _ctx(str(tmp_path), [{"file": "app.py", "start": 10, "end": 14}])
    findings = [_f("semgrep", "app.py", 12)]
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert len(kept) == 1
    assert dropped == 0


def test_filter_drops_sast_outside_range(tmp_path) -> None:
    ctx = _ctx(str(tmp_path), [{"file": "app.py", "start": 10, "end": 14}])
    findings = [_f("semgrep", "app.py", 30)]
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert kept == []
    assert dropped == 1


def test_filter_respects_tolerance(tmp_path) -> None:
    """Semgrep often points at the rule's anchor, a couple lines off the sink."""
    ctx = _ctx(str(tmp_path), [{"file": "app.py", "start": 10, "end": 14}])
    # 16 is within default tolerance=2 (end was 14)
    findings = [_f("semgrep", "app.py", 16)]
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert len(kept) == 1
    assert dropped == 0


def test_filter_passes_through_non_sast_sources(tmp_path) -> None:
    """Gitleaks, grype, and ai_discovery findings are NOT line-filtered."""
    ctx = _ctx(str(tmp_path), [{"file": "app.py", "start": 10, "end": 14}])
    findings = [
        _f("gitleaks", "app.py", 99),
        _f("grype", "requirements.txt", 1),
        _f("ai_discovery", "app.py", 99),
    ]
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert len(kept) == 3
    assert dropped == 0


def test_filter_passes_through_findings_with_no_line(tmp_path) -> None:
    ctx = _ctx(str(tmp_path), [{"file": "app.py", "start": 10, "end": 14}])
    findings = [{"source": "semgrep", "file_path": "app.py"}]  # no start_line
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert len(kept) == 1
    assert dropped == 0


def test_filter_no_op_when_no_ranges_in_context(tmp_path) -> None:
    """If we have no line-range info at all, pass everything through —
    silently over-dropping is the worse failure mode."""
    ctx = _ctx(str(tmp_path), [])
    findings = [_f("semgrep", "app.py", 999)]
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert len(kept) == 1
    assert dropped == 0


def test_filter_keeps_sast_when_file_has_no_recorded_ranges(tmp_path) -> None:
    """File is in changed_files but we have ranges only for OTHER files —
    don't drop, that's a data-incompleteness case not an off-diff case."""
    ctx = _ctx(str(tmp_path), [{"file": "other.py", "start": 1, "end": 5}])
    findings = [_f("semgrep", "app.py", 50)]
    kept, dropped = _restrict_to_pr_diff_lines(findings, ctx)
    assert len(kept) == 1
    assert dropped == 0
