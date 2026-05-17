"""Unit tests for the normalizer's co-location dedup (Phase 2.5) and
PR-diff scope filter."""

from __future__ import annotations

from secureflow.agents.normalizer import normalize


def _f(
    *, fid: str, source: str, severity: str = "high", conf: float = 0.7,
    rule_id: str = "rule.a", file_path: str = "app.py",
    start_line: int = 10, end_line: int = 10, title: str = "thing",
) -> dict:
    return {
        "id": fid, "source": source, "rule_id": rule_id, "title": title,
        "description": title, "file_path": file_path,
        "start_line": start_line, "end_line": end_line,
        "severity": severity, "confidence": conf,
        "cwe": [], "owasp": [], "mitre_attack": [], "cve": [],
        "reachability": "unknown", "false_positive": False,
        "patch_status": "none",
    }


def test_same_scanner_same_line_collapsed_to_one() -> None:
    state = {
        "sast_findings": [
            _f(fid="a"*16, source="semgrep", rule_id="rule.django.sqli", severity="medium"),
            _f(fid="b"*16, source="semgrep", rule_id="rule.flask.sqli", severity="high"),
            _f(fid="c"*16, source="semgrep", rule_id="rule.sqlalchemy.sqli", severity="medium"),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 1
    f = out["normalized_findings"][0]
    # The "high" one wins.
    assert f["severity"] == "high"
    assert f["rule_id"] == "rule.flask.sqli"
    # Other rule IDs preserved in the description.
    assert "rule.django.sqli" in f["description"]
    assert "rule.sqlalchemy.sqli" in f["description"]


def test_different_lines_not_collapsed() -> None:
    state = {
        "sast_findings": [
            _f(fid="a"*16, source="semgrep", start_line=10, end_line=10),
            _f(fid="b"*16, source="semgrep", start_line=20, end_line=20),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 2


def test_different_files_not_collapsed() -> None:
    state = {
        "sast_findings": [
            _f(fid="a"*16, source="semgrep", file_path="a.py"),
            _f(fid="b"*16, source="semgrep", file_path="b.py"),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 2


def test_different_sources_not_collapsed() -> None:
    state = {
        "secret_findings": [_f(fid="a"*16, source="gitleaks", severity="critical")],
        "sast_findings":   [_f(fid="b"*16, source="semgrep")],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 2


def test_gitleaks_never_collapsed_even_same_line() -> None:
    # Two distinct secrets on the same line → both kept (rare but legal).
    state = {
        "secret_findings": [
            _f(fid="a"*16, source="gitleaks", rule_id="aws-key", severity="critical"),
            _f(fid="b"*16, source="gitleaks", rule_id="stripe-key", severity="critical"),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 2


def test_dependency_findings_without_path_not_collapsed() -> None:
    state = {
        "dependency_findings": [
            _f(fid="a"*16, source="grype", file_path=None, start_line=None,
               title="CVE-A"),
            _f(fid="b"*16, source="grype", file_path=None, start_line=None,
               title="CVE-B"),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 2


# ───────────────────────────────────── PR-diff scope filter tests ──


def test_findings_outside_pr_diff_are_dropped() -> None:
    """The normalizer should keep only findings on files in the PR diff —
    otherwise scanner-walked findings on pre-existing code leak into the
    PR review and misattribute blame to the PR author."""
    state = {
        "pr_context": {
            "repo_path": ".",
            "changed_files": ["demo_app/app.py"],
        },
        "sast_findings": [
            _f(fid="a"*16, source="semgrep", file_path="demo_app/app.py",
               start_line=14, title="In-diff SQLi"),
            _f(fid="b"*16, source="semgrep",
               file_path="secureflow/agents/ai_discovery_agent.py",
               start_line=101, title="Pre-existing logger format"),
        ],
    }
    out = normalize(state)
    titles = [f["title"] for f in out["normalized_findings"]]
    assert "In-diff SQLi" in titles
    assert "Pre-existing logger format" not in titles
    assert len(out["normalized_findings"]) == 1


def test_no_pr_context_keeps_all_findings() -> None:
    """Local non-PR scans (no `pr_context`) should not be filtered."""
    state = {
        "sast_findings": [
            _f(fid="a"*16, source="semgrep", file_path="anywhere/foo.py"),
            _f(fid="b"*16, source="semgrep", file_path="elsewhere/bar.py",
               start_line=20),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 2


def test_empty_changed_files_keeps_all_findings() -> None:
    """`changed_files: []` (no diff context, e.g. local repo walk fallback)
    means scan-everything — don't filter."""
    state = {
        "pr_context": {"repo_path": ".", "changed_files": []},
        "sast_findings": [
            _f(fid="a"*16, source="semgrep", file_path="anywhere.py"),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 1


def test_dependency_findings_without_path_kept_regardless() -> None:
    """Findings without a file_path (e.g. some grype CVEs) shouldn't be
    dropped by the diff filter — they have no path to match against."""
    state = {
        "pr_context": {
            "repo_path": ".",
            "changed_files": ["requirements.txt"],
        },
        "dependency_findings": [
            _f(fid="a"*16, source="grype", file_path=None, start_line=None,
               title="CVE-no-path"),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 1


def test_path_normalization_handles_windows_and_absolute() -> None:
    """Semgrep on Windows sometimes emits absolute paths with backslashes
    while git diff emits POSIX-relative ones. Both should match."""
    import os
    cwd_posix = os.getcwd().replace("\\", "/")
    state = {
        "pr_context": {
            "repo_path": ".",
            "changed_files": ["app.py"],  # git-diff style
        },
        "sast_findings": [
            _f(fid="a"*16, source="semgrep",
               # Mixed-case test: absolute Windows-style path that resolves
               # to the same repo-relative `app.py`.
               file_path=f"{cwd_posix}/app.py".replace("/", os.sep)),
        ],
    }
    out = normalize(state)
    assert len(out["normalized_findings"]) == 1
