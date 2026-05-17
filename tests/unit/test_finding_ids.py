"""Unit tests for the stable finding-ID algorithm (design/05 §3)."""

from __future__ import annotations

from secureflow.schemas.ids import code_fingerprint, compute_finding_id


def test_same_inputs_produce_same_id() -> None:
    a = compute_finding_id(
        source="gitleaks", title="Hardcoded AWS key",
        file_path="config.py", rule_id="aws-access-key",
        start_line=12, end_line=12, code="AKIAIOSFODNN7EXAMPLE",
    )
    b = compute_finding_id(
        source="gitleaks", title="Hardcoded AWS key",
        file_path="config.py", rule_id="aws-access-key",
        start_line=12, end_line=12, code="AKIAIOSFODNN7EXAMPLE",
    )
    assert a == b
    assert len(a) == 16


def test_id_is_stable_across_whitespace_and_comments() -> None:
    original = compute_finding_id(
        source="semgrep", title="SQLi", file_path="app.py", rule_id="python.sqli",
        start_line=5, end_line=7, code='q = "SELECT * FROM users WHERE id = " + uid',
    )
    reformatted = compute_finding_id(
        source="semgrep", title="SQLi", file_path="app.py", rule_id="python.sqli",
        start_line=5, end_line=7,
        code='q   =   "SELECT * FROM users WHERE id = " + uid   # added comment',
    )
    assert original == reformatted


def test_id_changes_on_structural_fix() -> None:
    before = compute_finding_id(
        source="semgrep", title="SQLi", file_path="app.py", rule_id="python.sqli",
        start_line=5, end_line=7, code='q = "SELECT * FROM users WHERE id = " + uid',
    )
    after = compute_finding_id(
        source="semgrep", title="SQLi", file_path="app.py", rule_id="python.sqli",
        start_line=5, end_line=7, code='cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
    )
    assert before != after


def test_secret_value_swap_keeps_id_stable() -> None:
    a = compute_finding_id(
        source="gitleaks", title="AWS key", file_path="config.py",
        rule_id="aws-access-key", start_line=3, end_line=3,
        code='AWS_KEY = "AKIA1234567890ABCDEF"',
    )
    b = compute_finding_id(
        source="gitleaks", title="AWS key", file_path="config.py",
        rule_id="aws-access-key", start_line=3, end_line=3,
        code='AWS_KEY = "AKIA0987654321FEDCBA"',
    )
    assert a == b


def test_fingerprint_handles_empty_code() -> None:
    assert code_fingerprint("") == "0" * 8
    assert code_fingerprint("   \n\t  ") == code_fingerprint("")


def test_different_files_yield_different_ids() -> None:
    a = compute_finding_id(
        source="semgrep", title="X", file_path="a.py", rule_id="r",
        code="bad()",
    )
    b = compute_finding_id(
        source="semgrep", title="X", file_path="b.py", rule_id="r",
        code="bad()",
    )
    assert a != b
