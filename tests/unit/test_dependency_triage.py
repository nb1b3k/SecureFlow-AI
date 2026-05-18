"""Tests for dependency triage — manifest parsing + scope classification.

Policy-integration tests for triage live alongside the W1 policy-profiles
work since the dev-deps downgrade reads the `profile` field on
PolicyConfig. This file covers only the parser + scope helper that ship
in W5.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from secureflow.tools.manifest_parser import (
    normalize,
    parse_manifests,
)

# ---------- normalize ----------

def test_normalize_lowercases_and_dedupes_separators() -> None:
    assert normalize("SQLAlchemy") == "sqlalchemy"
    assert normalize("flask_login") == "flask-login"
    assert normalize("python-dotenv") == "python-dotenv"
    assert normalize("  some.package  ") == "some-package"


# ---------- package.json ----------

def test_package_json_separates_runtime_and_dev(tmp_path: Path) -> None:
    pkg = {
        "name": "x",
        "dependencies": {"express": "^4.0.0", "lodash": "^4.0.0"},
        "devDependencies": {"jest": "^29.0.0", "eslint": "^8.0.0"},
        "peerDependencies": {"react": "^18.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    direct = parse_manifests(str(tmp_path), ["package.json"])
    assert direct.runtime == {"express", "lodash", "react"}
    assert direct.dev == {"jest", "eslint"}


# ---------- pyproject.toml (PEP 621) ----------

def test_pyproject_pep621(tmp_path: Path) -> None:
    body = textwrap.dedent("""
        [project]
        name = "x"
        dependencies = [
            "requests>=2.0",
            "pydantic[email]>=2",
            "click; python_version<'3.12'",
        ]

        [project.optional-dependencies]
        dev = ["pytest", "ruff>=0.5"]
        docs = ["mkdocs>=1"]
        prod-extras = ["uvicorn"]
    """).strip()
    (tmp_path / "pyproject.toml").write_text(body)
    direct = parse_manifests(str(tmp_path), ["pyproject.toml"])
    assert direct.runtime == {"requests", "pydantic", "click", "uvicorn"}
    assert direct.dev == {"pytest", "ruff", "mkdocs"}


# ---------- pyproject.toml (Poetry) ----------

def test_pyproject_poetry(tmp_path: Path) -> None:
    body = textwrap.dedent("""
        [tool.poetry]
        name = "x"
        version = "0"

        [tool.poetry.dependencies]
        python = "^3.11"
        requests = "^2"
        django = "^5"

        [tool.poetry.group.dev.dependencies]
        pytest = "^8"
        black = "^24"

        [tool.poetry.group.test.dependencies]
        coverage = "^7"
    """).strip()
    (tmp_path / "pyproject.toml").write_text(body)
    direct = parse_manifests(str(tmp_path), ["pyproject.toml"])
    assert direct.runtime == {"requests", "django"}
    assert direct.dev == {"pytest", "black", "coverage"}


# ---------- Pipfile ----------

def test_pipfile(tmp_path: Path) -> None:
    body = textwrap.dedent("""
        [packages]
        flask = "*"
        gunicorn = "*"

        [dev-packages]
        pytest = "*"
    """).strip()
    (tmp_path / "Pipfile").write_text(body)
    direct = parse_manifests(str(tmp_path), ["Pipfile"])
    assert direct.runtime == {"flask", "gunicorn"}
    assert direct.dev == {"pytest"}


# ---------- requirements*.txt ----------

def test_requirements_runtime_vs_dev(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.0\nrequests>=2\n# comment\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest\nblack\n-r requirements.txt\n")
    direct = parse_manifests(
        str(tmp_path), ["requirements.txt", "requirements-dev.txt"]
    )
    assert direct.runtime == {"flask", "requests"}
    assert direct.dev == {"pytest", "black"}


def test_requirements_skips_urls_and_flags(tmp_path: Path) -> None:
    body = textwrap.dedent("""
        flask
        git+https://github.com/foo/bar.git
        -e .
        -r other.txt
        https://example.com/pkg.whl
    """).strip()
    (tmp_path / "requirements.txt").write_text(body)
    direct = parse_manifests(str(tmp_path), ["requirements.txt"])
    assert direct.runtime == {"flask"}


# ---------- parser failure tolerance ----------

def test_parse_missing_file_returns_empty(tmp_path: Path) -> None:
    direct = parse_manifests(str(tmp_path), ["package.json"])
    assert direct.is_empty


def test_parse_malformed_manifest_does_not_raise(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{ not valid json")
    direct = parse_manifests(str(tmp_path), ["package.json"])
    assert direct.is_empty


def test_parse_rejects_path_traversal(tmp_path: Path) -> None:
    """A crafted manifest path that escapes the repo root must be ignored."""
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "package.json").write_text(
        '{"dependencies": {"evil": "1.0.0"}}'
    )
    direct = parse_manifests(str(repo), ["../outside/package.json"])
    # The path resolved outside the repo, so the parser skipped it.
    assert direct.is_empty


def test_parse_skips_oversized_manifest(tmp_path: Path) -> None:
    """A manifest larger than the cap is skipped to bound memory use."""
    # 3 MiB of repeated bytes — over the 2 MiB cap.
    (tmp_path / "package.json").write_text("x" * (3 * 1024 * 1024))
    direct = parse_manifests(str(tmp_path), ["package.json"])
    assert direct.is_empty
