"""AI Vulnerability Discovery agent.

Calls the configured LLM with the PR diff + code context and converts the
strict-JSON `AIDiscoveryResponse` into `Finding` dicts.

If the LLM is unavailable (no API key, stub provider, budget exceeded),
this agent returns no findings and records the reason in `scanner_errors`.
The orchestrator continues with scanner findings only.
"""

from __future__ import annotations

from secureflow.config import Config
from secureflow.llm import (
    BudgetExceededError,
    BudgetTracker,
    ContentAddressedCache,
    LLMError,
    PromptRegistry,
)
from secureflow.llm.factory import build_llm_client
from secureflow.schemas.ids import compute_finding_id
from secureflow.schemas.llm_outputs import AIDiscoveryResponse
from secureflow.utils.logging import get_logger

log = get_logger("agent.ai_discovery")


def _skip(reason: str) -> dict:
    return {
        "ai_discovery_findings": [],
        "scanner_errors": {"ai_discovery": reason},
    }


def ai_discovery(state: dict) -> dict:
    cfg = Config.model_validate(state.get("config") or {})
    pr_context = state.get("pr_context") or {}

    if not cfg.ai_discovery.enabled:
        return _skip("disabled in config")

    # Skip when no relevant changes
    if not pr_context.get("changed_files"):
        return _skip("no changed files")

    if (
        not pr_context.get("sensitive_files_changed")
        and not cfg.ai_discovery.run_on_all_prs
    ):
        return _skip("no sensitive files changed")

    # Build code context. In real PR scans there's a git diff; for ad-hoc
    # scans of a directory (no .git, or no prior commit), we fall back to
    # loading the sensitive file contents directly so the model still has
    # code to reason about.
    repo_path = pr_context.get("repo_path") or "."
    diff = pr_context.get("diff") or ""
    changed_files = pr_context.get("changed_files") or []
    if not diff.strip():
        contents = _load_file_contents(repo_path, changed_files)
        if not contents.strip():
            return _skip("empty diff and no readable file contents")
        code_context = contents
    else:
        code_context = _changed_files_header(changed_files)

    cache = ContentAddressedCache(enabled=cfg.llm.cache)
    budget = BudgetTracker(limits=cfg.limits)
    try:
        client = build_llm_client(cfg, cache=cache, budget=budget)
    except Exception as e:
        log.info("LLM unavailable: %s", e)
        return _skip(f"llm_unavailable: {type(e).__name__}")

    try:
        prompt = PromptRegistry().get("ai_discovery", "v1")
    except FileNotFoundError as e:
        log.warning("missing prompt: %s", e)
        return _skip(f"prompt_missing: {e}")

    user = prompt.render_user(code_context=code_context, diff=_truncate(diff, 12_000))

    try:
        result = client.complete(
            system=prompt.system,
            user=user,
            schema=AIDiscoveryResponse,
            prompt_version=prompt.prompt_version,
            temperature=cfg.llm.temperature,
            max_tokens=cfg.llm.max_tokens,
        )
    except BudgetExceededError as e:
        return _skip(f"budget_exceeded: {e}")
    except LLMError as e:
        return _skip(f"llm_error: {e}")
    except Exception as e:
        return _skip(f"llm_exception: {type(e).__name__}")

    findings = [_to_finding_dict(item, prompt.prompt_version) for item in result.parsed.findings]
    log.info(
        "ai discovery complete: %d findings (tokens_in=%d tokens_out=%d cache_hit=%s)",
        len(findings), result.tokens_in, result.tokens_out, result.cache_hit,
    )
    return {
        "ai_discovery_findings": findings,
        "budget_used": {
            "tokens_in": result.tokens_in,
            "tokens_out": result.tokens_out,
            "llm_calls": 0 if result.cache_hit else 1,
        },
        "prompt_versions": {"ai_discovery": result.prompt_version},
    }


# ──────────────────────────────────────────────────────────── helpers ──


def _changed_files_header(files: list[str]) -> str:
    return "Files changed in this PR:\n" + "\n".join(f"- {f}" for f in files[:50])


def _load_file_contents(
    repo_path: str,
    files: list[str],
    *,
    max_files: int = 6,
    max_bytes_per_file: int = 8_000,
) -> str:
    """Read the most relevant changed files into a single code-context block.

    Used when there is no git diff (ad-hoc scan of a non-git directory). The
    AI Discovery prompt can still reason about whole-file content; this also
    matches how a human reviewer would approach a small codebase.
    """
    from pathlib import Path

    parts: list[str] = []
    # Prefer source files (.py/.js/.ts/...) over yaml/markdown when picking
    # the budget-bounded subset.
    sorted_files = sorted(
        files,
        key=lambda f: (
            0 if Path(f).suffix in {".py", ".js", ".ts", ".tsx", ".go", ".rb", ".java"} else 1,
            f,
        ),
    )
    for rel in sorted_files[:max_files]:
        full = Path(repo_path) / rel
        if not full.exists() or not full.is_file():
            continue
        try:
            body = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(body) > max_bytes_per_file:
            body = body[:max_bytes_per_file] + "\n... [truncated]"
        parts.append(f"FILE: {rel}\n{body}")
    return "\n\n".join(parts)


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"\n... [{len(s) - n} chars truncated]"


def _to_finding_dict(item, prompt_version: str) -> dict:
    fid = compute_finding_id(
        source="ai_discovery",
        title=item.title,
        file_path=item.file_path,
        rule_id=None,
        symbol=None,
        start_line=item.start_line,
        end_line=item.end_line,
        code=item.evidence,
    )
    return {
        "id": fid,
        "source": "ai_discovery",
        "rule_id": None,
        "title": item.title,
        "description": item.description,
        "file_path": item.file_path,
        "start_line": item.start_line,
        "end_line": item.end_line,
        "symbol": None,
        "severity": item.severity,
        "confidence": item.confidence,
        "evidence": item.evidence,
        "cwe": [],
        "owasp": [],
        "mitre_attack": [],
        "cve": [],
        "reachability": "unknown",
        "exploitability": None,
        "attacker_scenario": item.exploit_scenario,
        "impact": None,
        "false_positive": False,
        "false_positive_reason": None,
        "recommendation": item.recommendation,
        "patch_unified_diff": None,
        "patch_explanation": None,
        "patch_status": "not_applicable",
        "patch_verification_notes": None,
        "prompt_version": prompt_version,
    }
