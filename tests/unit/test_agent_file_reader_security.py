"""Security tests for the LLM agents' file-reader fallbacks.

Both `ai_discovery_agent._load_file_contents` and
`threat_model_agent._load_changed_files` accept a `files` list derived
from the PR diff and read file contents from disk to build the LLM
prompt. A crafted path like `../../etc/passwd` must NOT escape
`repo_path`. Same threat model as `manifest_parser.parse_manifests`
was hardened against (see README §"Self-review evidence" — caught by
the bot's own self-scan).
"""

from __future__ import annotations

from pathlib import Path

from secureflow.agents.ai_discovery_agent import _load_file_contents
from secureflow.agents.threat_model_agent import _load_changed_files


def test_ai_discovery_load_skips_path_traversal(tmp_path: Path) -> None:
    """A path that resolves outside `repo_path` must not be read."""
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("DO NOT LEAK")
    (repo / "innocent.py").write_text("print('hi')")

    result = _load_file_contents(
        str(repo),
        ["../outside/secret.txt", "innocent.py"],
    )
    assert "DO NOT LEAK" not in result, "path-traversal entry leaked file contents"
    assert "innocent.py" in result, "legitimate file should still load"


def test_ai_discovery_load_skips_oversized_file(tmp_path: Path) -> None:
    """A pathologically large file must not be read into memory."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "huge.py").write_text("x" * (100 * 1024))
    (repo / "small.py").write_text("print('hi')")

    result = _load_file_contents(str(repo), ["huge.py", "small.py"])
    assert "small.py" in result
    assert "huge.py" not in result


def test_threat_model_load_skips_path_traversal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("DO NOT LEAK")
    (repo / "main.tf").write_text('resource "aws_s3_bucket" "x" {}')

    result = _load_changed_files(str(repo), ["../outside/secret.txt", "main.tf"])
    assert "DO NOT LEAK" not in result
    assert "main.tf" in result


def test_threat_model_load_skips_oversized_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "huge.tf").write_text("x" * (100 * 1024))
    (repo / "small.tf").write_text("// small terraform")

    result = _load_changed_files(str(repo), ["huge.tf", "small.tf"])
    assert "small.tf" in result
    assert "huge.tf" not in result


def test_ai_discovery_handles_missing_file_silently(tmp_path: Path) -> None:
    """Missing file is not an error — agent skips and moves on."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("ok")
    result = _load_file_contents(str(repo), ["nonexistent.py", "real.py"])
    assert "real.py" in result
    assert "nonexistent.py" not in result


def test_threat_model_handles_empty_files_list(tmp_path: Path) -> None:
    """Empty files list returns empty string, not an exception."""
    repo = tmp_path / "repo"
    repo.mkdir()
    assert _load_changed_files(str(repo), []) == ""
