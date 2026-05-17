"""Tests for the deterministic confidence floor on tainted SAST findings.

Why this exists: live xlang eval on PR #2 of nb1b3k/secureflow-ai-pr-test
revealed that semgrep auto reports cross-language SAST findings at
confidence 0.40, below the policy FAIL threshold (0.50). A high-severity
Go SQLi was therefore classified PASS. The floor fires only when:

- source is SAST (semgrep/bandit/sast)
- severity >= medium
- rule_id matches a known sink family (sqli, command-injection, xxe, ...)
- the file's content within ±8 lines of the finding contains a tainted
  input pattern (request.args, r.URL.Query, $_GET, params[:, etc.)

This way the floor is genuinely "the LLM would have done this too" — it
just runs unconditionally so the deterministic baseline isn't worse than
scanners-only when LLM is unavailable.
"""

from __future__ import annotations

from pathlib import Path

from secureflow.agents.normalizer import _apply_taint_floor, _has_taint_nearby, _is_known_sink_rule


def _finding(**overrides) -> dict:
    base = {
        "id": "f1",
        "source": "semgrep",
        "rule_id": "go.lang.security.audit.database.string-formatted-query.string-formatted-query",
        "title": "SQLi",
        "description": "SQLi",
        "file_path": "app.go",
        "start_line": 17,
        "end_line": 18,
        "severity": "high",
        "confidence": 0.40,
    }
    base.update(overrides)
    return base


def _write_go_file(tmp_path: Path) -> None:
    (tmp_path / "app.go").write_text(
        "package main\n"
        "import \"fmt\"\n"
        "func getUser(w http.ResponseWriter, r *http.Request) {\n"
        "    uid := r.URL.Query().Get(\"id\")\n"
        "    q := fmt.Sprintf(\"SELECT * FROM u WHERE id = %s\", uid)\n"
        "    db.Query(q)\n"
        "}\n",
        encoding="utf-8",
    )


def test_known_sink_rule_substring_match() -> None:
    assert _is_known_sink_rule("go.lang.security.audit.database.string-formatted-query")
    assert _is_known_sink_rule("python.flask.security.injection.SQLi-tainted-sql-string")
    assert _is_known_sink_rule("ruby.lang.security.dangerous-subshell.dangerous-subshell")
    assert _is_known_sink_rule("XSS-Raw-Html-Format")  # case-insensitive
    assert not _is_known_sink_rule("python.lang.correctness.unused-import")
    assert not _is_known_sink_rule(None)
    assert not _is_known_sink_rule("")


def test_taint_nearby_detects_go_url_query(tmp_path: Path) -> None:
    """The taint check reads the actual file, not the finding's evidence,
    so it works even when CI's semgrep returns `requires login` snippets."""
    _write_go_file(tmp_path)
    f = _finding(file_path="app.go", start_line=5)  # the fmt.Sprintf line
    assert _has_taint_nearby(f, tmp_path) is True


def test_taint_nearby_misses_when_no_request_source(tmp_path: Path) -> None:
    (tmp_path / "calc.go").write_text(
        "package main\n"
        "func sumTwo(a, b int) int { return a + b }\n",
        encoding="utf-8",
    )
    f = _finding(file_path="calc.go", start_line=2)
    assert _has_taint_nearby(f, tmp_path) is False


def test_taint_nearby_works_for_php_superglobal(tmp_path: Path) -> None:
    (tmp_path / "lookup.php").write_text(
        "<?php\n$id = $_GET['id'];\n"
        "$q = \"SELECT * FROM users WHERE id = \" . $id;\n"
        "mysqli_query($conn, $q);\n",
        encoding="utf-8",
    )
    f = _finding(file_path="lookup.php", start_line=3)
    assert _has_taint_nearby(f, tmp_path) is True


def test_floor_lifts_low_confidence_sqli(tmp_path: Path) -> None:
    """The headline test: a 0.40 high-severity SQLi with tainted input
    near the sink gets floored to 0.7."""
    _write_go_file(tmp_path)
    findings = [_finding(start_line=5)]  # the fmt.Sprintf line in _write_go_file
    out, floored = _apply_taint_floor(findings, {"repo_path": str(tmp_path)})
    assert floored == 1
    assert out[0]["confidence"] == 0.7


def test_floor_skips_when_severity_too_low(tmp_path: Path) -> None:
    _write_go_file(tmp_path)
    f = _finding(severity="low")
    out, floored = _apply_taint_floor([f], {"repo_path": str(tmp_path)})
    assert floored == 0
    assert out[0]["confidence"] == 0.4


def test_floor_skips_when_confidence_already_high(tmp_path: Path) -> None:
    _write_go_file(tmp_path)
    f = _finding(confidence=0.85)
    out, floored = _apply_taint_floor([f], {"repo_path": str(tmp_path)})
    assert floored == 0
    assert out[0]["confidence"] == 0.85


def test_floor_skips_when_rule_not_a_known_sink(tmp_path: Path) -> None:
    _write_go_file(tmp_path)
    f = _finding(rule_id="python.lang.correctness.unused-import")
    out, floored = _apply_taint_floor([f], {"repo_path": str(tmp_path)})
    assert floored == 0
    assert out[0]["confidence"] == 0.4


def test_floor_skips_non_sast_sources(tmp_path: Path) -> None:
    _write_go_file(tmp_path)
    f = _finding(source="gitleaks")
    out, floored = _apply_taint_floor([f], {"repo_path": str(tmp_path)})
    assert floored == 0
    assert out[0]["confidence"] == 0.4


def test_floor_skips_when_no_taint_visible(tmp_path: Path) -> None:
    (tmp_path / "calc.go").write_text(
        "package main\n"
        "func sumTwo(a, b int) int { return a + b }\n",
        encoding="utf-8",
    )
    f = _finding(file_path="calc.go", start_line=2)
    out, floored = _apply_taint_floor([f], {"repo_path": str(tmp_path)})
    assert floored == 0
    assert out[0]["confidence"] == 0.4


def test_floor_handles_missing_file_gracefully(tmp_path: Path) -> None:
    """If the file isn't on disk (e.g., scanner reported on a deleted
    path), we don't crash — we just don't floor."""
    f = _finding(file_path="never_existed.go", start_line=1)
    out, floored = _apply_taint_floor([f], {"repo_path": str(tmp_path)})
    assert floored == 0
    assert out[0]["confidence"] == 0.4
