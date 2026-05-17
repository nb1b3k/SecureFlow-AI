"""Checkov subprocess wrapper for static IaC / DevOps-config findings.

Checkov is a static analyser from Bridgecrew/Prisma Cloud that covers:
Terraform, Dockerfile, Docker Compose, Kubernetes manifests, Helm,
CloudFormation, Serverless, GitHub Actions workflows, ARM templates,
and committed IAM / S3 bucket / security-group policy JSON files. We
use the JSON output and let `iac_agent` do the normalization.

CLI shape: `checkov -d <repo> -o json --quiet --soft-fail`.

  - `-d` over `-f` so a single invocation covers every IaC frame in the
    repo. The agent post-filters to PR-scope.
  - `--soft-fail` makes Checkov exit 0 regardless of findings (default
    is exit 1 on any finding, which would look like a tool error). We
    score severity ourselves in the policy engine.
  - `--quiet` suppresses Checkov's banner / progress output. Without
    this, stdout begins with ASCII art before the JSON object and
    `json.loads` blows up.

Checkov sometimes emits TWO objects on stdout: one for IaC frameworks
that scanned, one for the secrets framework when enabled. We tolerate
both by trying JSON, then JSONL, then a single object.
"""

from __future__ import annotations

import json
from typing import Any

from secureflow.utils.logging import get_logger
from secureflow.utils.subprocess_utils import run

log = get_logger("checkov")


def run_checkov(repo_path: str) -> list[dict]:
    """Run checkov over `repo_path` and return raw failed_checks records.

    Returns an empty list on tool-missing, timeout, or unparseable output —
    the agent surfaces those as `scanner_errors[checkov]` so the pipeline
    keeps going instead of dying on a tool quirk.

    Flags minimised after pre-prod debugging:
      - Earlier versions passed `--skip-framework secrets` and `--no-guide`.
        Pre-prod CI showed Checkov producing 0 findings on a Terraform
        file that locally produced dozens — strongly suggesting one of
        those flags was interfering with framework selection in Checkov
        3.2. We now pass only the minimum-viable args and let Checkov
        scan every framework it can. Gitleaks-vs-Checkov secrets
        double-reporting is rare in practice; if it shows up, we'll
        re-add the skip via the canonical CSV-style argument.
      - `-o json` lands the JSON on stdout, NOT in a file. Some Checkov
        flags (e.g. `--output-file-path`) divert output and would make
        us read empty stdout. Sticking with the default keeps things
        simple.
    """
    cmd = [
        "checkov",
        "-d", repo_path,
        "-o", "json",
        "--quiet",
        "--soft-fail",
    ]
    r = run(cmd, timeout=300)
    if r.timed_out:
        log.warning("checkov timed out after 300s")
        return []
    raw = (r.stdout or "").strip()
    # Diagnostic logging so CI failures are debuggable without a re-run.
    # We log shape, not content, to keep secret-y bits out of logs.
    log.info(
        "checkov subprocess returned",
        extra={
            "returncode": r.returncode,
            "stdout_len": len(raw),
            "stderr_len": len(r.stderr or ""),
            "stdout_head": raw[:200],
        },
    )
    if not raw:
        # Empty stdout. Surface the stderr head so we have a clue.
        log.warning(
            "checkov produced empty stdout",
            extra={"stderr_head": (r.stderr or "")[:300]},
        )
        return []
    return _extract_failed_checks(raw)


def _extract_failed_checks(raw: str) -> list[dict]:
    """Pull `failed_checks` out of whichever JSON shape Checkov produced.

    Three observed shapes:
      1. Single object `{"results": {"failed_checks": [...]}}` (one framework).
      2. List of objects `[{...}, {...}]` (multi-framework run).
      3. Newline-delimited objects when both IaC + secrets frameworks ran.

    Anything we can't parse → empty list + warning. Better to under-report
    than to crash the orchestrator on a tool quirk.
    """
    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError:
        items: list[Any] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        if not items:
            log.warning("checkov produced unparseable output (first 200 chars): %s", raw[:200])
            return []
        parsed = items

    results: list[dict] = []
    blocks = parsed if isinstance(parsed, list) else [parsed]
    passed_total = failed_total = 0
    frameworks_seen: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        framework = block.get("check_type") or block.get("framework")
        if framework:
            frameworks_seen.append(framework)
        block_results = (block.get("results") or {}).get("failed_checks") or []
        block_passed = (block.get("results") or {}).get("passed_checks") or []
        passed_total += len(block_passed) if isinstance(block_passed, list) else 0
        failed_total += len(block_results) if isinstance(block_results, list) else 0
        for fc in block_results:
            if isinstance(fc, dict):
                fc.setdefault("_framework", framework)
                results.append(fc)
    # Diagnostic — when Checkov runs but finds 0 failures we want to know
    # whether it actually scanned anything. Passed-checks count > 0 means
    # rules ran and PASSED on this repo; passed=0 AND failed=0 usually means
    # the framework parser couldn't make sense of the input (e.g. Terraform
    # registry deps weren't resolvable from the workflow runner's cwd).
    log.info(
        "checkov json extracted",
        extra={
            "frameworks": frameworks_seen,
            "passed_total": passed_total,
            "failed_total": failed_total,
        },
    )
    return results
