"""Parse changed package manifests to classify dependencies.

Used by the dependency agent to label each Grype/OSV finding as
`direct_runtime`, `direct_dev`, or `transitive`. The classification
drives policy decisions: transitive and dev findings get downgraded
relative to direct runtime, which dramatically reduces dependency-scan
noise on real PRs.

This parser deliberately does **not** read lockfiles. Lockfiles contain
the full transitive graph; we only need the direct-dependency set
(what the developer actually declared) to make the runtime/transitive
distinction. Package names are normalized so PyPI's case-insensitive
matching works (PEP 503).
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DirectDeps:
    """Sets of normalized package names declared as direct dependencies."""

    runtime: set[str] = field(default_factory=set)
    dev: set[str] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not self.runtime and not self.dev

    def merge(self, other: DirectDeps) -> None:
        self.runtime |= other.runtime
        self.dev |= other.dev


def normalize(name: str) -> str:
    """PEP 503-style normalization for cross-ecosystem matching.

    npm package names are case-sensitive but lowercase-only by
    convention, so lowercasing is safe there too. Replacing `_` with `-`
    handles `setup_tools` vs `setuptools`-style variation.
    """
    return re.sub(r"[-_.]+", "-", name.strip().lower())


_MAX_MANIFEST_BYTES = 2 * 1024 * 1024  # 2 MiB — package.json in the wild is <300KB


def parse_manifests(repo_path: str, manifest_paths: list[str]) -> DirectDeps:
    """Walk the changed manifests and return the union of direct deps.

    Unknown manifests, missing files, and parse failures are skipped
    silently — the dependency agent treats a fully empty result as
    "classification unavailable" and falls back to `unknown` scope.

    Defense-in-depth: `manifest_paths` is derived from the PR diff, but
    a crafted PR could include `../../etc/passwd`. We reject any path
    that resolves outside `repo_path`. Also caps manifest file size so a
    pathologically large file can't OOM the parser.
    """
    out = DirectDeps()
    repo = Path(repo_path).resolve()
    for rel in manifest_paths:
        full = (repo / rel).resolve()
        try:
            full.relative_to(repo)
        except ValueError:
            # Resolved path escapes the repository root — skip.
            continue
        if not full.exists() or not full.is_file():
            continue
        try:
            if full.stat().st_size > _MAX_MANIFEST_BYTES:
                continue
        except OSError:
            continue
        try:
            sub = _dispatch(full)
        except Exception:
            # Defensive: a malformed manifest must not break the scan.
            continue
        if sub is not None:
            out.merge(sub)
    return out


def _dispatch(path: Path) -> DirectDeps | None:
    name = path.name
    lower = name.lower()
    if lower == "package.json":
        return _parse_package_json(path)
    if lower == "pyproject.toml":
        return _parse_pyproject(path)
    if lower == "pipfile":
        return _parse_pipfile(path)
    if re.match(r"requirements.*\.txt$", lower):
        return _parse_requirements(path, name=lower)
    if lower == "setup.py" or lower == "setup.cfg":
        # Skipping — install_requires parsing needs a real exec/configparser
        # pass that's not worth the surface area for a v1 triage feature.
        return None
    return None


# -------- package.json --------

def _parse_package_json(path: Path) -> DirectDeps:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = DirectDeps()
    for key in ("dependencies", "peerDependencies", "optionalDependencies"):
        for pkg in (data.get(key) or {}):
            out.runtime.add(normalize(pkg))
    for pkg in (data.get("devDependencies") or {}):
        out.dev.add(normalize(pkg))
    return out


# -------- pyproject.toml --------

def _parse_pyproject(path: Path) -> DirectDeps:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out = DirectDeps()

    # PEP 621 [project] table.
    project = data.get("project") or {}
    for raw in project.get("dependencies") or []:
        n = _strip_requirement_name(raw)
        if n:
            out.runtime.add(normalize(n))
    optional = project.get("optional-dependencies") or {}
    for group_name, items in optional.items():
        bucket = out.dev if _is_dev_group(group_name) else out.runtime
        for raw in items or []:
            n = _strip_requirement_name(raw)
            if n:
                bucket.add(normalize(n))

    # Poetry layout.
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    for pkg, _ in (poetry.get("dependencies") or {}).items():
        if pkg.lower() == "python":  # Poetry stores the interpreter pin here
            continue
        out.runtime.add(normalize(pkg))
    # Legacy `[tool.poetry.dev-dependencies]`.
    for pkg in (poetry.get("dev-dependencies") or {}):
        out.dev.add(normalize(pkg))
    # Modern `[tool.poetry.group.<name>.dependencies]`.
    groups = (poetry.get("group") or {})
    for group_name, body in groups.items():
        deps = (body or {}).get("dependencies") or {}
        bucket = out.dev if _is_dev_group(group_name) else out.runtime
        for pkg in deps:
            if pkg.lower() == "python":
                continue
            bucket.add(normalize(pkg))

    return out


# -------- Pipfile --------

def _parse_pipfile(path: Path) -> DirectDeps:
    """Pipfile is TOML with `[packages]` and `[dev-packages]` sections."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out = DirectDeps()
    for pkg in (data.get("packages") or {}):
        out.runtime.add(normalize(pkg))
    for pkg in (data.get("dev-packages") or {}):
        out.dev.add(normalize(pkg))
    return out


# -------- requirements*.txt --------

_REQ_FILE_DEV_TOKENS = ("dev", "test", "ci", "lint", "docs")


def _parse_requirements(path: Path, *, name: str) -> DirectDeps:
    """Heuristic: filename containing `dev`/`test`/`ci`/etc. => dev bucket."""
    is_dev = any(tok in name for tok in _REQ_FILE_DEV_TOKENS)
    out = DirectDeps()
    bucket = out.dev if is_dev else out.runtime
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            # Skip comments and pip flags like `-r other.txt` / `-e .`.
            continue
        pkg = _strip_requirement_name(line)
        if pkg:
            bucket.add(normalize(pkg))
    return out


# -------- helpers --------

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")


def _strip_requirement_name(spec: str) -> str | None:
    """Pull the package name out of a PEP 508 spec.

    Handles `pkg`, `pkg==1.0`, `pkg>=1,<2`, `pkg[extra]==1.0`,
    `pkg; python_version<"3.10"`. Returns `None` for URL/path
    requirements (those have no canonical name to match against).
    """
    s = spec.split(";", 1)[0].strip()
    if s.startswith(("http://", "https://", "git+", "file:")):
        return None
    s = s.split("[", 1)[0]
    m = _REQ_NAME_RE.match(s)
    return m.group(1) if m else None


def _is_dev_group(group_name: str) -> bool:
    g = group_name.lower()
    return g in {"dev", "test", "tests", "testing", "ci", "lint", "docs", "doc"}
