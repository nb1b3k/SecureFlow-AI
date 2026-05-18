"""W19: tests for the `scanners.grype.include_transitive` toggle.

The toggle filters dependency-agent output post-classification. When
False, findings tagged `dependency_scope=transitive` are dropped.
`unknown` scope is preserved on purpose so unsupported ecosystems
(Go, Rust, Java, Ruby, PHP, .NET) don't silently lose visibility.
"""

from __future__ import annotations

from unittest.mock import patch

from secureflow.agents.dependency_agent import dependency_scan


def _grype_match(pkg_name: str, location: str, severity: str = "High") -> dict:
    """Build a synthetic Grype JSON match — enough fields for the agent."""
    return {
        "vulnerability": {
            "id": f"CVE-2024-{abs(hash(pkg_name)) % 100000:05d}",
            "severity": severity,
            "description": f"Synthetic CVE in {pkg_name}",
            "cwes": ["CWE-79"],
            "fix": {"versions": ["9.9.9"]},
        },
        "artifact": {
            "name": pkg_name,
            "version": "1.0.0",
            "locations": [{"path": location}],
        },
    }


def _pr_state(repo_path: str, *, include_transitive: bool = True) -> dict:
    return {
        "pr_context": {
            "repo_path": repo_path,
            "changed_files": ["requirements.txt"],
        },
        "config": {
            "scanners": {
                "grype": {"enabled": True, "include_transitive": include_transitive},
            },
        },
    }


def test_default_keeps_transitive(tmp_path):
    """Default `include_transitive=True` preserves the historic full-tree
    report — same shape as before W19."""
    (tmp_path / "requirements.txt").write_text("flask==2.0\n")
    fake = [
        _grype_match("flask", "requirements.txt"),
        _grype_match("werkzeug", "requirements.txt"),  # transitive of flask
    ]
    with patch("secureflow.agents.dependency_agent.run_grype", return_value=fake):
        out = dependency_scan(_pr_state(str(tmp_path)))
    findings = out["dependency_findings"]
    assert len(findings) == 2
    by_scope = {f["symbol"].split("@")[0]: f["dependency_scope"] for f in findings}
    assert by_scope == {"flask": "direct_runtime", "werkzeug": "transitive"}


def test_include_transitive_false_drops_transitive(tmp_path):
    """W19 contract: with the toggle off, transitive findings disappear."""
    (tmp_path / "requirements.txt").write_text("flask==2.0\n")
    fake = [
        _grype_match("flask", "requirements.txt"),
        _grype_match("werkzeug", "requirements.txt"),
        _grype_match("jinja2", "requirements.txt"),
    ]
    with patch("secureflow.agents.dependency_agent.run_grype", return_value=fake):
        out = dependency_scan(_pr_state(str(tmp_path), include_transitive=False))
    findings = out["dependency_findings"]
    # Only the direct runtime dep (flask) survives.
    assert len(findings) == 1
    assert findings[0]["dependency_scope"] == "direct_runtime"
    assert findings[0]["symbol"].startswith("flask@")


def test_include_transitive_false_preserves_unknown(tmp_path):
    """Safe-default: `unknown` scope is preserved even when the toggle is
    off. Unparsed manifest formats (go.mod, Cargo.toml, pom.xml, etc.)
    must not silently lose findings."""
    # Note: go.mod is NOT parsed by manifest_parser today, so the direct
    # set will be empty and everything classifies as `unknown`.
    (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.22\n")
    state = {
        "pr_context": {
            "repo_path": str(tmp_path),
            "changed_files": ["go.mod"],
        },
        "config": {
            "scanners": {"grype": {"enabled": True, "include_transitive": False}},
        },
    }
    fake = [_grype_match("github.com/foo/bar", "go.mod")]
    with patch("secureflow.agents.dependency_agent.run_grype", return_value=fake):
        out = dependency_scan(state)
    findings = out["dependency_findings"]
    # `unknown` scope finding survives even with toggle off.
    assert len(findings) == 1
    assert findings[0]["dependency_scope"] == "unknown"


def test_default_when_config_omitted(tmp_path):
    """No `config` key in state — pydantic uses defaults, transitive kept."""
    (tmp_path / "requirements.txt").write_text("flask==2.0\n")
    fake = [
        _grype_match("flask", "requirements.txt"),
        _grype_match("werkzeug", "requirements.txt"),
    ]
    state = {"pr_context": {"repo_path": str(tmp_path), "changed_files": ["requirements.txt"]}}
    with patch("secureflow.agents.dependency_agent.run_grype", return_value=fake):
        out = dependency_scan(state)
    assert len(out["dependency_findings"]) == 2  # default = keep
