"""Static IaC / DevOps-config agent (Checkov-backed).

Sits in the parallel-scanner layer alongside `secrets_scan`, `sast_scan`,
`dependency_scan`, and `ai_discovery`. Its job is to call Checkov over
the repo and emit normalized `Finding`s for misconfigurations in
Terraform / Dockerfile / Compose / Kubernetes / Helm / CloudFormation /
GitHub Actions workflows / committed IAM and bucket policy JSONs.

Scope guard: like the dependency agent, this skips when the PR touches
zero IaC-shaped files. Without the guard, every PR (even a one-line
Python doc change) would trigger a full Checkov walk that returns
findings unrelated to the PR — noise the normalizer's PR-scope filter
would then immediately drop. The guard saves CI time and makes the
"why didn't this PR get an IaC scan?" question answerable from logs.

No live cloud access. No AWS / Azure / GCP credentials required.
Everything is static repo inspection.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from secureflow.config import Config
from secureflow.schemas.finding import Severity
from secureflow.schemas.ids import compute_finding_id
from secureflow.tools.checkov_runner import run_checkov
from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import ToolNotFoundError

log = get_logger("agent.iac")

# Files that legitimately belong to the IaC / DevOps surface area.
# Order matters only for readability; the patterns are tried as a set.
_IAC_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Terraform.
    re.compile(r"(^|/)[^/]+\.tf$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]+\.tfvars$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]+\.tf\.json$", re.IGNORECASE),
    # Docker.
    re.compile(r"(^|/)Dockerfile[^/]*$"),  # Dockerfile, Dockerfile.prod, …
    re.compile(r"(^|/)docker-compose[^/]*\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)compose\.ya?ml$", re.IGNORECASE),
    # Kubernetes manifests — heuristic, since k8s YAML is just YAML. We
    # match on common directory names and on file names with k8s-shaped
    # suffixes; the actual content is sniffed by Checkov.
    re.compile(r"(^|/)(k8s|kubernetes|manifests|deploy(?:ment)?s?)/.*\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)(deployment|service|ingress|configmap|secret|namespace|role|"
               r"rolebinding|clusterrole|clusterrolebinding)[^/]*\.ya?ml$", re.IGNORECASE),
    # Helm.
    re.compile(r"(^|/)Chart\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)values\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)templates/[^/]+\.ya?ml$", re.IGNORECASE),
    # GitHub Actions workflows.
    re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE),
    # CloudFormation / Serverless / SAM.
    re.compile(r"(^|/)cloudformation[^/]*\.(ya?ml|json)$", re.IGNORECASE),
    re.compile(r"(^|/)serverless[^/]*\.(ya?ml|json)$", re.IGNORECASE),
    re.compile(r"(^|/)template[^/]*\.(ya?ml|json)$", re.IGNORECASE),
    # ARM / Bicep.
    re.compile(r"(^|/)[^/]+\.bicep$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]+\.arm\.json$", re.IGNORECASE),
    # Committed IAM / bucket / SG policy JSON — fragile heuristic, kept
    # narrow so a random `package.json` doesn't trigger a Checkov walk.
    re.compile(r"(^|/)(iam|policies?|s3|bucket|security[-_]?groups?)/.*\.json$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]*(iam|policy|bucket-policy|sg)[^/]*\.json$", re.IGNORECASE),
)

# Map Checkov severity (when set) → our Severity. Many CKV checks omit
# severity entirely; we floor at "medium" so misconfigs aren't silently
# ignored. The policy engine still requires high+confident to FAIL.
_CHECKOV_SEV_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}

# Known-dangerous Checkov check IDs that we promote to "high" regardless
# of Checkov's own severity field. These are the IaC equivalents of
# "critical CVE" — the kind of thing that historically causes breaches.
# Keep this list short and well-justified; bloat dilutes its signal.
_HIGH_RISK_CHECKS: frozenset[str] = frozenset({
    # AWS S3 — public buckets.
    "CKV_AWS_18",   # S3 bucket logging
    "CKV_AWS_19",   # S3 SSE
    "CKV_AWS_20",   # S3 not public read
    "CKV_AWS_21",   # S3 versioning
    "CKV_AWS_53",   # Block public ACLs
    "CKV_AWS_54",   # Block public policy
    "CKV_AWS_55",   # Block public ACLs (account)
    "CKV_AWS_56",   # Restrict public buckets
    # AWS IAM — wildcard permissions.
    "CKV_AWS_1",    # No wildcard in IAM policy Action
    "CKV_AWS_40",   # No wildcard in IAM policy Resource
    "CKV_AWS_49",   # No NotActions
    "CKV_AWS_62",   # No wildcard in role assume policy
    "CKV_AWS_107",  # Admin-* policies
    # AWS security groups — open to world.
    "CKV_AWS_24",   # No 0.0.0.0/0 ingress on port 22
    "CKV_AWS_25",   # No 0.0.0.0/0 ingress on port 3389
    "CKV_AWS_260",  # No 0.0.0.0/0 on any TCP port
    # Docker — running as root, ADD over COPY, latest tag.
    "CKV_DOCKER_3", # USER must be set
    "CKV_DOCKER_4", # ADD only when needed (COPY preferred)
    # GitHub Actions — overprivileged workflows / unsafe patterns.
    "CKV2_GHA_1",   # Top-level permissions set
    "CKV_GHA_3",    # No unsecure commands enabled
    "CKV_GHA_7",    # No setting GITHUB_TOKEN to write-all
})


def _is_iac(path: str) -> bool:
    norm = str(PurePosixPath(path.replace("\\", "/")))
    return any(p.search(norm) for p in _IAC_PATTERNS)


def _changed_iac_files(changed_files: list[str]) -> list[str]:
    return [f for f in changed_files if _is_iac(f)]


def _severity_for(check: dict) -> Severity:
    """Map a Checkov failed_check record to a `Severity`.

    Precedence:
      1. High-risk check ID → at least "high".
      2. Checkov's own `severity` field if present.
      3. "medium" default — misconfigs are rarely info-level.
    """
    check_id = check.get("check_id") or ""
    raw = (check.get("severity") or "").upper()
    base = _CHECKOV_SEV_MAP.get(raw, "medium")
    if check_id in _HIGH_RISK_CHECKS:
        # Bump but don't downgrade: if Checkov already said "critical",
        # keep "critical".
        if base in ("info", "low", "medium"):
            return "high"
    return base


def _norm_path(repo_path: str, raw: str | None) -> str | None:
    """Convert a Checkov path to a repo-relative POSIX path matching what
    `git diff --name-only` emits (no leading slash, forward slashes).

    Checkov emits two distinct path keys per failed_check:

      - `file_path`     : path relative to the `-d <dir>` target (often
                          `\\main.tf` on Windows, `/main.tf` on Linux).
                          USELESS for the normalizer's PR-scope filter
                          when the IaC lives in a subdirectory.
      - `repo_file_path`: path relative to the repo root, POSIX-style,
                          with a single leading slash (e.g.
                          `/iac_demo/main.tf`).  This is the one we
                          want — just strip the leading slash.

    `iac_scan` passes `repo_file_path` in here. This helper cleans up
    the leading slash plus any backslashes so the result composes with
    the normalizer's PR-scope filter on both Windows and Linux.
    """
    if not raw:
        return None
    s = raw.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    if s.startswith("/"):
        s = s[1:]
    return s


def iac_scan(state: dict) -> dict:
    """Run Checkov over the repo and emit normalized IaC findings.

    Skipped (with a logged reason) when:
      - The scanner is disabled in `scanners.checkov`.
      - The PR touches zero IaC-shaped files.
      - Checkov is not installed.
    """
    pr_context = state.get("pr_context") or {}
    repo_path = pr_context.get("repo_path") or state.get("repo_path") or "."
    changed_files = list(pr_context.get("changed_files") or [])
    cfg = Config.model_validate(state.get("config") or {})

    if not cfg.scanners.checkov.enabled:
        log.info("checkov disabled in config; skipping iac scan")
        return {
            "iac_findings": [],
            "scanner_errors": {"checkov": "disabled in config"},
        }

    iac_files = _changed_iac_files(changed_files)
    if changed_files and not iac_files:
        log.info(
            "no IaC files in this PR; skipping iac scan",
            extra={"changed_files": len(changed_files)},
        )
        return {
            "iac_findings": [],
            "scanner_errors": {"checkov": "skipped: no IaC files changed"},
        }

    log.info("iac scan starting", extra={"iac_files": iac_files, "iac_file_count": len(iac_files)})

    try:
        raw = run_checkov(repo_path)
    except ToolNotFoundError:
        log.info("checkov not installed; skipping iac scan")
        return {
            "iac_findings": [],
            "scanner_errors": {"checkov": "not installed"},
        }
    except Exception as e:  # noqa: BLE001 - scanner faults must not kill the run
        log.warning("checkov failed: %s", e)
        return {
            "iac_findings": [],
            "scanner_errors": {"checkov": f"{type(e).__name__}: {e}"[:300]},
        }

    findings: list[dict] = []
    for check in raw:
        check_id = check.get("check_id") or "checkov-rule"
        check_name = check.get("check_name") or check_id
        # `repo_file_path` is repo-rooted (e.g. `/iac_demo/main.tf`);
        # `file_path` is relative to Checkov's `-d` target and is
        # therefore useless for the PR-scope filter in the normalizer
        # whenever the IaC lives in a subdirectory. Prefer the former,
        # fall back to the latter only when Checkov omits it.
        raw_path = check.get("repo_file_path") or check.get("file_path")
        file_path = _norm_path(repo_path, raw_path)
        line_range = check.get("file_line_range") or [None, None]
        start_line = line_range[0] if isinstance(line_range, list) and line_range else None
        end_line = line_range[1] if isinstance(line_range, list) and len(line_range) > 1 else start_line
        resource = check.get("resource") or check.get("_framework") or ""
        guideline = check.get("guideline") or ""
        code_block = check.get("code_block") or []
        # Checkov's code_block is a list of [line_no, "line text"] tuples.
        # Flatten to a snippet that fits Finding.evidence (capped to keep
        # the LLM prompt budget bounded).
        snippet_parts: list[str] = []
        if isinstance(code_block, list):
            for entry in code_block[:25]:
                if isinstance(entry, list) and len(entry) >= 2:
                    snippet_parts.append(str(entry[1]).rstrip())
                elif isinstance(entry, str):
                    snippet_parts.append(entry.rstrip())
        snippet = "\n".join(snippet_parts)[:2000]

        finding_id = compute_finding_id(
            source="checkov",
            title=check_name,
            file_path=file_path,
            rule_id=check_id,
            symbol=resource or None,
            start_line=start_line,
            end_line=end_line,
            code=snippet,
        )

        # OWASP A05:2021 covers security misconfiguration — most Checkov
        # findings live there. A06 (Vulnerable & Outdated Components) is
        # for image / dependency CVEs which we get from grype instead.
        owasp = ["A05:2021-Security Misconfiguration"]

        recommendation = (
            guideline
            or f"Review Checkov check {check_id} ({check_name}) and remediate per the linked policy."
        )

        findings.append({
            "id": finding_id,
            "source": "checkov",
            "rule_id": check_id,
            "title": check_name[:200],
            "description": (check.get("description") or check_name)[:1000],
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "symbol": resource or None,
            "severity": _severity_for(check),
            # Checkov is rule-based deterministic analysis — confidence is
            # high. We reserve room above 0.85 so the LLM exploitability
            # pass can still bump truly egregious findings.
            "confidence": 0.85,
            "evidence": snippet,
            "cwe": [],
            "owasp": owasp,
            "mitre_attack": [],
            "cve": [],
            "references": [guideline] if guideline else [],
            "reachability": "unknown",
            "exploitability": None,
            "attacker_scenario": None,
            "impact": None,
            "false_positive": False,
            "false_positive_reason": None,
            "recommendation": recommendation,
            "patch_unified_diff": None,
            "patch_explanation": None,
            "patch_status": "none",
            "patch_verification_notes": None,
            "prompt_version": None,
        })

    log.info("iac scan complete", extra={"findings": len(findings), "iac_files": len(iac_files)})
    return {"iac_findings": findings}
