"""Grype runner + finding normalizer.

Diff-scoped: the dependency scan only runs when the PR's `changed_files`
include a recognized package manifest. Without this scope, grype would
scan the project's system Python deps on every PR and produce dozens of
unrelated CVE findings.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from secureflow.config import Config
from secureflow.schemas.finding import Severity
from secureflow.schemas.ids import compute_finding_id
from secureflow.tools.grype_runner import run_grype
from secureflow.tools.manifest_parser import DirectDeps, normalize, parse_manifests
from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import ToolNotFoundError

log = get_logger("agent.dependency")

_GRYPE_SEV_MAP: dict[str, Severity] = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "info",
    "Unknown": "low",
}

# Files that legitimately introduce or update dependencies. Anything outside
# this list is ignored by the dependency scope check.
_MANIFEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(^|/)requirements[^/]*\.txt$", re.IGNORECASE),
    re.compile(r"(^|/)pyproject\.toml$", re.IGNORECASE),
    re.compile(r"(^|/)Pipfile(\.lock)?$", re.IGNORECASE),
    re.compile(r"(^|/)poetry\.lock$", re.IGNORECASE),
    re.compile(r"(^|/)setup\.py$", re.IGNORECASE),
    re.compile(r"(^|/)setup\.cfg$", re.IGNORECASE),
    re.compile(r"(^|/)package\.json$", re.IGNORECASE),
    re.compile(r"(^|/)package-lock\.json$", re.IGNORECASE),
    re.compile(r"(^|/)yarn\.lock$", re.IGNORECASE),
    re.compile(r"(^|/)pnpm-lock\.yaml$", re.IGNORECASE),
    re.compile(r"(^|/)go\.mod$", re.IGNORECASE),
    re.compile(r"(^|/)go\.sum$", re.IGNORECASE),
    re.compile(r"(^|/)Gemfile(\.lock)?$", re.IGNORECASE),
    re.compile(r"(^|/)Cargo\.(toml|lock)$", re.IGNORECASE),
    re.compile(r"(^|/)composer\.(json|lock)$", re.IGNORECASE),
    re.compile(r"(^|/)Dockerfile[^/]*$", re.IGNORECASE),
    re.compile(r"(^|/).*\.(csproj|fsproj|vbproj)$", re.IGNORECASE),
    re.compile(r"(^|/)pom\.xml$", re.IGNORECASE),
    re.compile(r"(^|/)build\.(gradle|gradle\.kts|sbt)$", re.IGNORECASE),
)


def _is_manifest(path: str) -> bool:
    norm = str(PurePosixPath(path.replace("\\", "/")))
    return any(p.search(norm) for p in _MANIFEST_PATTERNS)


def _changed_manifests(changed_files: list[str]) -> list[str]:
    return [f for f in changed_files if _is_manifest(f)]


def dependency_scan(state: dict) -> dict:
    pr_context = state.get("pr_context") or {}
    repo_path = pr_context.get("repo_path") or "."
    changed_files = list(pr_context.get("changed_files") or [])
    manifests = _changed_manifests(changed_files)
    cfg = Config.model_validate(state.get("config") or {})
    include_transitive = cfg.scanners.grype.include_transitive

    # Scope guard: skip the scan entirely when no dependency manifests changed.
    if changed_files and not manifests:
        log.info(
            "no dependency manifests in this PR; skipping dependency scan",
            extra={"changed_files": len(changed_files)},
        )
        return {
            "dependency_findings": [],
            "scanner_errors": {"grype": "skipped: no dependency manifests changed"},
        }

    log.info(
        "dependency scan starting",
        extra={"manifests": manifests, "manifest_count": len(manifests)},
    )

    try:
        matches = run_grype(repo_path)
    except ToolNotFoundError:
        log.info("grype not installed; skipping dependency scan")
        return {
            "dependency_findings": [],
            "scanner_errors": {"grype": "not installed"},
        }
    except Exception as e:
        log.warning("grype failed: %s", e)
        return {
            "dependency_findings": [],
            "scanner_errors": {"grype": f"{type(e).__name__}: {e}"[:300]},
        }

    # When we have a set of changed manifests, restrict grype's findings to
    # artifacts located in (or under) those manifests. This filters out the
    # system Python deps that grype reports on every repo by default.
    if manifests:
        manifest_set = {str(PurePosixPath(m.replace("\\", "/"))) for m in manifests}
        matches = [m for m in matches if _match_in_manifests(m, manifest_set)]

    # Build the direct-dependency set from the PR's changed manifests. If
    # parsing yields nothing (no recognized manifests, parse failures), all
    # findings stay at `dependency_scope=unknown` and the policy engine
    # treats them as before — no regression.
    direct = parse_manifests(repo_path, manifests)
    log.info(
        "direct dependency classification ready",
        extra={
            "direct_runtime": len(direct.runtime),
            "direct_dev": len(direct.dev),
        },
    )

    findings: list[dict] = []
    for m in matches:
        vuln = m.get("vulnerability", {}) or {}
        artifact = m.get("artifact", {}) or {}
        cve = vuln.get("id") or "UNKNOWN"
        severity = _GRYPE_SEV_MAP.get(vuln.get("severity", "Unknown"), "low")
        pkg_name = artifact.get("name", "?")
        pkg_version = artifact.get("version", "?")
        fix_versions = (vuln.get("fix", {}) or {}).get("versions") or []

        title = f"{cve} in {pkg_name} {pkg_version}"
        finding_id = compute_finding_id(
            source="grype",
            title=title,
            file_path=None,
            rule_id=cve,
            symbol=f"{pkg_name}@{pkg_version}",
            code=cve,
        )

        rec_parts = [f"Upgrade {pkg_name} from {pkg_version}"]
        if fix_versions:
            rec_parts.append(f"to one of: {', '.join(fix_versions)}.")
        else:
            rec_parts.append("to a fixed version once one is published.")

        scope = _classify_scope(pkg_name, direct)

        # W19: drop transitive findings when the user opted out of the
        # full SBOM-style report. `unknown` is preserved on purpose —
        # for ecosystems the manifest_parser doesn't yet cover (Go,
        # Rust, Java, etc.) we'd rather show a finding than silently
        # hide it.
        if not include_transitive and scope == "transitive":
            continue

        findings.append({
            "id": finding_id,
            "source": "grype",
            "rule_id": cve,
            "title": title,
            "description": vuln.get("description") or title,
            "file_path": None,
            "start_line": None,
            "end_line": None,
            "symbol": f"{pkg_name}@{pkg_version}",
            "severity": severity,
            "confidence": 0.90,
            "evidence": None,
            "cwe": [c for c in (vuln.get("cwes") or []) if isinstance(c, str)],
            "owasp": ["A06:2021-Vulnerable and Outdated Components"],
            "mitre_attack": [],
            "cve": [cve] if cve.startswith("CVE-") or cve.startswith("GHSA-") else [],
            "reachability": "unknown",
            "exploitability": None,
            "attacker_scenario": None,
            "impact": None,
            "false_positive": False,
            "false_positive_reason": None,
            "recommendation": " ".join(rec_parts),
            "patch_unified_diff": None,
            "patch_explanation": None,
            "patch_status": "none",
            "patch_verification_notes": None,
            "prompt_version": None,
            "dependency_scope": scope,
        })

    log.info(
        "dependency scan complete",
        extra={"findings": len(findings), "manifests": len(manifests)},
    )
    return {"dependency_findings": findings}


def _classify_scope(pkg_name: str, direct: DirectDeps) -> str:
    """Tag the finding's package as direct_runtime / direct_dev / transitive / unknown.

    When no manifests were parseable, every finding stays `unknown` and the
    policy engine treats the scan exactly as it did before triage shipped.
    """
    if direct.is_empty:
        return "unknown"
    norm = normalize(pkg_name)
    if norm in direct.runtime:
        return "direct_runtime"
    if norm in direct.dev:
        return "direct_dev"
    return "transitive"


def _match_in_manifests(match: dict, manifest_paths: set[str]) -> bool:
    """True if grype reported the dep at a location overlapping our manifests."""
    artifact = match.get("artifact", {}) or {}
    locations = artifact.get("locations") or []
    for loc in locations:
        path = loc.get("path") if isinstance(loc, dict) else None
        if not path:
            continue
        norm = str(PurePosixPath(path.replace("\\", "/").lstrip("/")))
        # Match if the artifact's location is any of the changed manifest
        # paths or under one of them (e.g. a lockfile in a subdir).
        for mpath in manifest_paths:
            if norm == mpath or norm.endswith("/" + mpath) or mpath.endswith(norm):
                return True
    return False
