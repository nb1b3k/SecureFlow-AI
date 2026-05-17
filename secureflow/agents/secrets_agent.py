"""Gitleaks runner + finding normalizer.

If gitleaks isn't installed, the scan is recorded under `scanner_errors`
and the pipeline continues.
"""

from __future__ import annotations

from secureflow.schemas.finding import Severity
from secureflow.schemas.ids import compute_finding_id
from secureflow.tools.gitleaks_runner import run_gitleaks
from secureflow.utils.logging import get_logger
from secureflow.utils.secret_masker import mask
from secureflow.utils.subprocess_utils import ToolNotFoundError

log = get_logger("agent.secrets")


def _severity_for_rule(rule_id: str) -> Severity:
    rid = (rule_id or "").lower()
    if any(k in rid for k in ("aws", "private-key", "stripe", "jwt", "gcp", "github-pat")):
        return "critical"
    return "high"


def secrets_scan(state: dict) -> dict:
    pr_context = state.get("pr_context") or {}
    repo_path = pr_context.get("repo_path") or "."
    try:
        raw = run_gitleaks(repo_path)
    except ToolNotFoundError:
        log.info("gitleaks not installed; skipping secrets scan")
        return {
            "secret_findings": [],
            "scanner_errors": {"gitleaks": "not installed"},
        }
    except Exception as e:  # subprocess / parsing failure
        log.warning("gitleaks failed: %s", e)
        return {
            "secret_findings": [],
            "scanner_errors": {"gitleaks": f"{type(e).__name__}: {e}"[:300]},
        }

    findings: list[dict] = []
    for item in raw:
        rule_id = item.get("RuleID") or item.get("Rule") or "gitleaks-rule"
        file_path = item.get("File")
        start_line = item.get("StartLine") or item.get("Line")
        end_line = item.get("EndLine") or start_line
        secret_value = item.get("Secret") or ""
        masked_evidence = mask(secret_value)
        title = item.get("Description") or f"Hardcoded secret: {rule_id}"
        severity = _severity_for_rule(rule_id)

        finding_id = compute_finding_id(
            source="gitleaks",
            title=title,
            file_path=file_path,
            rule_id=rule_id,
            symbol=None,
            start_line=start_line,
            end_line=end_line,
            code=secret_value,
        )

        findings.append({
            "id": finding_id,
            "source": "gitleaks",
            "rule_id": rule_id,
            "title": title,
            "description": (
                f"Gitleaks detected a hardcoded secret matching rule '{rule_id}'. "
                "Hardcoded credentials in source code can lead to unauthorized access."
            ),
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "symbol": None,
            "severity": severity,
            "confidence": 0.95,
            "evidence": masked_evidence,
            "cwe": ["CWE-798"],
            "owasp": ["A07:2021-Identification and Authentication Failures"],
            "mitre_attack": ["T1552.001"],
            "cve": [],
            "reachability": "unknown",
            "exploitability": None,
            "attacker_scenario": None,
            "impact": None,
            "false_positive": False,
            "false_positive_reason": None,
            "recommendation": (
                "Remove the hardcoded secret. Load it from an environment variable "
                "or a secrets manager (AWS Secrets Manager, Google Secret Manager, "
                "HashiCorp Vault). Rotate the exposed credential immediately."
            ),
            "patch_unified_diff": None,
            "patch_explanation": None,
            "patch_status": "none",
            "patch_verification_notes": None,
            "prompt_version": None,
        })

    log.info("secrets scan complete: %d findings", len(findings))
    return {"secret_findings": findings}
