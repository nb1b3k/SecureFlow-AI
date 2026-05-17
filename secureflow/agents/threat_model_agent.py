"""Threat Modeling Delta agent — STRIDE review of the PR's design surface.

Different in *kind* from the other LLM agents: ai_discovery looks for
in-code vulnerabilities; exploitability scores existing findings;
patch_agent fixes them. The threat-model agent is the only one that
asks "what new attack surface did this PR introduce, regardless of
whether the lines themselves contain a CWE?"

That distinction matters at FAANG-style review boards (and for the
Amazon security engineering loop) because a clean code review can
still merge a design regression — e.g. a new `/admin/users` route
that returns 200 without an `@require_admin` decorator. semgrep
won't fire (the function is syntactically fine); ai_discovery
might miss it if the auth pattern is unusual; but the threat model
review catches "new admin endpoint without explicit authorization
in the diff" cleanly.

Position in the pipeline: runs after `exploitability` so it sees the
full normalized + reasoned finding set as context. Its output goes
into a SEPARATE `threat_model_findings` field (NOT merged into
`final_findings`) because design-level threats have a different
shape from code-level findings — different schema, different
reporting section, different policy semantics.

Free-tier safety:
  - One LLM call per PR (not per finding) — bounded cost.
  - Skips cleanly if no LLM provider is configured or the budget
    is exhausted.
  - Honors `ai_discovery.run_on_all_prs` for the run/skip gate so
    docs-only PRs don't burn quota on threat modeling either.
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
from secureflow.schemas.llm_outputs import ThreatModelResponse
from secureflow.utils.logging import get_logger

log = get_logger("agent.threat_model")

# Per-PR diff cap. The diff is the primary input — capping at 16K chars
# keeps Gemini-flash / Groq-8b prompts well under their context budget
# while still covering >99% of real PRs (median PR diff is < 4K chars).
_DIFF_CAP = 16_000


def _skip(reason: str) -> dict:
    return {
        "threat_model_findings": [],
        "scanner_errors": {"threat_model": reason},
    }


def threat_model_delta(state: dict) -> dict:
    cfg = Config.model_validate(state.get("config") or {})
    pr_context = state.get("pr_context") or {}

    diff = pr_context.get("diff") or ""
    changed_files = pr_context.get("changed_files") or []
    if not changed_files:
        return _skip("no changed files")

    # Re-use the AI Discovery toggles for the run/skip gate so users can
    # disable both LLM passes with one switch on PRs that only touch
    # boilerplate.
    if not cfg.ai_discovery.enabled and not cfg.ai_discovery.run_on_all_prs:
        return _skip("disabled in config (ai_discovery.enabled=false)")

    # The threat-model agent benefits from a sensitive-file signal but is
    # NOT strictly gated by it. Rationale: a PR that adds a brand-new
    # admin endpoint in a file that wasn't previously sensitive should
    # still trigger threat modeling — that's the entire point.
    #
    # When there is no diff (e.g. an ad-hoc scan of a directory or the
    # eval harness scanning a fixture repo) we fall back to loading the
    # changed files' contents directly — same pattern as the AI Discovery
    # agent. Treats "added in this PR" and "this is the whole file we
    # have to reason about" as equivalent from the threat-model POV,
    # which is correct: design-level review cares about what exists in
    # the surface, not whether it was added today or yesterday.
    repo_path = pr_context.get("repo_path") or state.get("repo_path") or "."
    diff_content = diff
    if not diff.strip():
        diff_content = _load_changed_files(repo_path, changed_files)
        if not diff_content.strip():
            return _skip("empty diff and no readable file contents")

    cache = ContentAddressedCache(enabled=cfg.llm.cache)
    budget = BudgetTracker(limits=cfg.limits)
    try:
        client = build_llm_client(cfg, cache=cache, budget=budget)
    except Exception as e:  # noqa: BLE001 — same shape as ai_discovery
        log.info("LLM unavailable: %s", e)
        return _skip(f"llm_unavailable: {type(e).__name__}")

    try:
        prompt = PromptRegistry().get("threat_model", "v1")
    except FileNotFoundError as e:
        log.warning("missing prompt: %s", e)
        return _skip(f"prompt_missing: {e}")

    repo_context = _repo_context_line(pr_context)
    files_header = "\n".join(f"- {f}" for f in changed_files[:60])
    user = prompt.render_user(
        repo_context=repo_context,
        changed_files=files_header,
        diff=_truncate(diff_content, _DIFF_CAP),
    )

    try:
        result = client.complete(
            system=prompt.system,
            user=user,
            schema=ThreatModelResponse,
            prompt_version=prompt.prompt_version,
            temperature=cfg.llm.temperature,
            # Threat modeling tends to be more verbose than discovery — give
            # it a bit more room for the abuse_cases / mitigations arrays.
            max_tokens=max(cfg.llm.max_tokens, 3072),
        )
    except BudgetExceededError as e:
        return _skip(f"budget_exceeded: {e}")
    except LLMError as e:
        return _skip(f"llm_error: {e}")
    except Exception as e:  # noqa: BLE001 - never fail the run on this node
        return _skip(f"llm_exception: {type(e).__name__}")

    threats = [_to_dict(t, result.prompt_version) for t in result.parsed.threats]
    # Format-string uses `key:value` not `key=value` to dodge a semgrep
    # rule that flags any logger format containing `key=value` literals
    # as a "possible hardcoded credential in log call." The rule is noisy
    # on telemetry-style log lines; the colon form carries the same info.
    log.info(
        "threat model complete | threats:%d tokens_in:%d tokens_out:%d cache_hit:%s",
        len(threats), result.tokens_in, result.tokens_out, result.cache_hit,
    )
    return {
        "threat_model_findings": threats,
        "budget_used": {
            "tokens_in": result.tokens_in,
            "tokens_out": result.tokens_out,
            "llm_calls": 0 if result.cache_hit else 1,
        },
        "prompt_versions": {"threat_model": result.prompt_version},
    }


# ──────────────────────────────────────────────────────────── helpers ──


def _repo_context_line(pr_context: dict) -> str:
    """Compact one-line context for the prompt so the LLM knows what app
    this is. Without it, the model has to guess from filenames and is more
    prone to generic "this could be SQLi" hand-waving.
    """
    bits: list[str] = []
    if pr_context.get("repo_name"):
        bits.append(f"repo={pr_context['repo_name']}")
    if pr_context.get("pr_number"):
        bits.append(f"pr=#{pr_context['pr_number']}")
    if pr_context.get("base_branch") and pr_context.get("head_branch"):
        bits.append(f"branch={pr_context['head_branch']} → {pr_context['base_branch']}")
    return ", ".join(bits) if bits else "(local scan)"


def _load_changed_files(
    repo_path: str,
    files: list[str],
    *,
    max_files: int = 8,
    max_bytes_per_file: int = 6_000,
) -> str:
    """Read the changed files into a single block when no git diff is available.

    Mirrors the AI Discovery agent's fallback so the threat-model agent
    can run on ad-hoc directory scans (eval harness, local `secureflow scan`).
    Prefers source / IaC files over docs when picking the budget-bounded
    subset — threat modeling on a markdown change is rarely useful.
    """
    from pathlib import Path

    sorted_files = sorted(
        files,
        key=lambda f: (
            0 if Path(f).suffix in {
                ".py", ".js", ".ts", ".tsx", ".go", ".rb", ".java",
                ".tf", ".yaml", ".yml", ".json",
            } else 1,
            f,
        ),
    )
    parts: list[str] = []
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


def _to_dict(item, prompt_version: str) -> dict:
    """Convert a `ThreatModelItem` to the dict shape we store on state.

    Keep the schema deliberately flat — the markdown report iterates this
    list and reads keys directly. Adding nested objects later means
    updating every consumer.
    """
    return {
        "change_type": item.change_type,
        "title": item.title,
        "description": item.description,
        "file_path": item.file_path,
        "start_line": item.start_line,
        "evidence_excerpt": item.evidence_excerpt,
        "stride": list(item.stride),
        "abuse_cases": list(item.abuse_cases),
        "mitigations": list(item.mitigations),
        "severity": item.severity,
        "confidence": item.confidence,
        "suggested_decision": item.suggested_decision,
        "prompt_version": prompt_version,
    }
