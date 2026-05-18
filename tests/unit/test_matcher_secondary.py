"""W22: tests for matcher's secondary-finding credit.

Once a label matches one finding, additional findings on the same
target (same package@version for deps, same file for Checkov) count
as `secondary` rather than FP. The matcher's existing 1:1 label->TP
behavior is preserved.
"""

from __future__ import annotations

from secureflow.eval.matcher import match_findings_to_labels
from secureflow.eval.schema import ExpectedLabel


def _label(label_id: str, **kwargs) -> ExpectedLabel:
    return ExpectedLabel.model_validate({
        "id": label_id,
        "type": kwargs.get("type", "vulnerable_dependency"),
        "file": kwargs.get("file", "requirements.txt"),
        "expected_severity": kwargs.get("expected_severity", "high"),
        "expected_decision_contribution": kwargs.get("expected_decision_contribution", "FAIL"),
        "package": kwargs.get("package", None),
        "version": kwargs.get("version", None),
        "line_range": kwargs.get("line_range", None),
    })


def _grype_finding(pkg: str, version: str, cve: str) -> dict:
    return {
        "id": f"f-{cve}",
        "source": "grype",
        "rule_id": cve,
        "title": f"{cve} in {pkg} {version}",
        "file_path": None,
        "start_line": None,
        "end_line": None,
        "symbol": f"{pkg}@{version}",
        "severity": "high",
        "confidence": 0.9,
        "cwe": [],
        "owasp": [],
        "mitre_attack": [],
        "cve": [cve],
        "reachability": "unknown",
        "false_positive": False,
        "patch_status": "none",
        "recommendation": f"Upgrade {pkg}",
    }


def test_multiple_cves_on_same_dep_credit_as_secondary():
    """Headline W22 case: scenario_03-style. 1 label for Django CVEs; grype
    emits 5 separate Django CVE findings. Old: TP=1, FP=4. New: TP=1, FP=0, secondary=4."""
    label = _label("django_220_cves", package="django", version="2.2.0")
    findings = [
        _grype_finding("django", "2.2.0", "CVE-2019-12308"),
        _grype_finding("django", "2.2.0", "CVE-2019-14232"),
        _grype_finding("django", "2.2.0", "CVE-2019-14233"),
        _grype_finding("django", "2.2.0", "CVE-2019-14234"),
        _grype_finding("django", "2.2.0", "CVE-2019-14235"),
    ]
    m = match_findings_to_labels(findings, [label])
    assert m.tp == 1
    assert m.fp == 0
    assert m.secondary == 4
    assert m.matched_label_ids == ["django_220_cves"]


def test_different_package_findings_still_count_as_fp():
    """Unmatched packages should still be FP."""
    label = _label("django_220_cves", package="django", version="2.2.0")
    findings = [
        _grype_finding("django", "2.2.0", "CVE-2019-12308"),
        _grype_finding("urllib3", "1.24.1", "CVE-2019-11324"),
    ]
    m = match_findings_to_labels(findings, [label])
    assert m.tp == 1
    assert m.fp == 1
    assert m.secondary == 0


def test_different_version_same_pkg_is_fp():
    """A CVE on a DIFFERENT version is its own bug."""
    label = _label("django_220_cves", package="django", version="2.2.0")
    findings = [
        _grype_finding("django", "2.2.0", "CVE-2019-12308"),
        _grype_finding("django", "3.0.0", "CVE-2020-7471"),
    ]
    m = match_findings_to_labels(findings, [label])
    assert m.tp == 1
    assert m.fp == 1
    assert m.secondary == 0


def test_no_match_means_no_secondary():
    """If the primary label doesn't match, no secondary credit."""
    label = _label("django_220_cves", package="django", version="2.2.0")
    findings = [
        _grype_finding("flask", "1.0.0", "CVE-2018-1000656"),
        _grype_finding("flask", "1.0.0", "CVE-2019-1010083"),
    ]
    m = match_findings_to_labels(findings, [label])
    assert m.tp == 0
    assert m.fp == 2
    assert m.secondary == 0
    assert m.unmatched_label_ids == ["django_220_cves"]


def test_two_labels_independent_secondary_credit():
    """Each label gets its own secondary sweep."""
    labels = [
        _label("django_220_cves", package="django", version="2.2.0"),
        _label("requests_2200_cves", package="requests", version="2.20.0"),
    ]
    findings = [
        _grype_finding("django", "2.2.0", "CVE-2019-12308"),
        _grype_finding("django", "2.2.0", "CVE-2019-14232"),
        _grype_finding("django", "2.2.0", "CVE-2019-14233"),
        _grype_finding("requests", "2.20.0", "CVE-2018-18074"),
        _grype_finding("requests", "2.20.0", "CVE-2023-32681"),
    ]
    m = match_findings_to_labels(findings, labels)
    assert m.tp == 2
    assert m.fp == 0
    assert m.secondary == 3
