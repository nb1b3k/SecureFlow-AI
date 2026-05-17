"""Unit tests for the eval matcher."""

from __future__ import annotations

from secureflow.eval.matcher import match_findings_to_labels
from secureflow.eval.schema import ExpectedLabel


def _label(**kw) -> ExpectedLabel:
    base = {"id": "l1", "type": "sql_injection", "file": "app.py", "line_range": [10, 12]}
    base.update(kw)
    return ExpectedLabel.model_validate(base)


def _finding(**kw) -> dict:
    base = {
        "id": "f" * 16,
        "source": "semgrep",
        "rule_id": "python.flask.security.injection.sqli",
        "title": "SQL injection via concat",
        "file_path": "app.py",
        "start_line": 10,
        "end_line": 10,
        "severity": "high",
        "confidence": 0.8,
    }
    base.update(kw)
    return base


# ─────────────────────────────────────────────────────────── matching ──


def test_perfect_match() -> None:
    r = match_findings_to_labels([_finding()], [_label()])
    assert r.tp == 1 and r.fp == 0 and r.fn == 0
    assert r.matched_label_ids == ["l1"]


def test_no_match_by_type() -> None:
    """Same file/line but rule_id type doesn't match the label type."""
    f = _finding(rule_id="python.unrelated.warning", title="something else")
    r = match_findings_to_labels([f], [_label()])
    assert r.tp == 0 and r.fp == 1 and r.fn == 1


def test_no_match_by_path() -> None:
    f = _finding(file_path="other.py")
    r = match_findings_to_labels([f], [_label()])
    assert r.tp == 0 and r.fp == 1 and r.fn == 1


def test_match_within_line_tolerance() -> None:
    """Line 14 matches label range [10,12] because tolerance is 5."""
    f = _finding(start_line=14, end_line=14)
    r = match_findings_to_labels([f], [_label()])
    assert r.tp == 1


def test_no_match_outside_line_tolerance() -> None:
    """Line 30 is well outside the label's [10,12] range."""
    f = _finding(start_line=30, end_line=30)
    r = match_findings_to_labels([f], [_label()])
    assert r.tp == 0 and r.fp == 1 and r.fn == 1


def test_greedy_one_to_one_assignment() -> None:
    """Two findings, one label → 1 TP and 1 FP, not 2 TP."""
    fs = [_finding(id="a" * 16), _finding(id="b" * 16)]
    r = match_findings_to_labels(fs, [_label()])
    assert r.tp == 1 and r.fp == 1 and r.fn == 0


def test_ai_discovery_matches_via_title_keyword() -> None:
    f = _finding(
        source="ai_discovery",
        rule_id=None,
        title="Possible SQL injection in admin handler",
    )
    r = match_findings_to_labels([f], [_label()])
    assert r.tp == 1


def test_ai_discovery_with_wrong_title_does_not_match() -> None:
    f = _finding(
        source="ai_discovery",
        rule_id=None,
        title="Logging issue, not related",
    )
    r = match_findings_to_labels([f], [_label()])
    assert r.tp == 0 and r.fn == 1


def test_dependency_label_matches_grype_finding_by_pkg() -> None:
    label = _label(
        id="dep1", type="vulnerable_dependency",
        file="requirements.txt", line_range=None,
        # Pydantic ignores extra fields, but ExpectedLabel has pkg/version
        package="Django", version="2.2.0",
    )
    grype_finding = {
        "id": "x" * 16,
        "source": "grype",
        "rule_id": "CVE-2020-9402",
        "title": "CVE-2020-9402 in django 2.2.0",
        "file_path": None,
        "start_line": None,
        "end_line": None,
        "symbol": "django@2.2.0",
        "severity": "high",
        "confidence": 0.9,
    }
    r = match_findings_to_labels([grype_finding], [label])
    assert r.tp == 1


def test_dependency_label_does_not_match_wrong_package() -> None:
    label = _label(
        id="dep1", type="vulnerable_dependency",
        file="requirements.txt", line_range=None,
        package="Django", version="2.2.0",
    )
    grype_finding = {
        "id": "x" * 16,
        "source": "grype",
        "rule_id": "CVE-XXXX-YYYY",
        "title": "CVE in requests 2.20.0",
        "file_path": None,
        "symbol": "requests@2.20.0",
        "severity": "high",
        "confidence": 0.9,
    }
    r = match_findings_to_labels([grype_finding], [label])
    assert r.tp == 0 and r.fn == 1


def test_path_normalization_handles_backslashes_and_prefixes() -> None:
    """Finding path 'tests/fixtures/X/app.py' should match label 'app.py'
    when scenario_repo='tests/fixtures/X'."""
    f = _finding(file_path="tests\\fixtures\\X\\app.py")
    r = match_findings_to_labels(
        [f], [_label()], scenario_repo="tests/fixtures/X",
    )
    assert r.tp == 1
