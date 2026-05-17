"""Patch generation + verification (Phase 3, real implementation).

For each scanner-detected finding:
  1. Generate a unified-diff patch via the LLM.
  2. Apply the patch to a temp git worktree.
  3. Re-run the originating scanner against the worktree.
  4. Mark the finding `patch_status = verified` only if the rescan no
     longer reports the finding.

AI-only findings (source=ai_discovery) cannot be re-scanned the same
way, so they get a suggested patch with `patch_status = not_applicable`.

This is the differentiator: a verified patch is dramatically more credible
than a raw LLM suggestion. See `design/03_patch_validation.md`.
"""

from __future__ import annotations

import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from secureflow.config import Config
from secureflow.llm import (
    BudgetExceededError,
    BudgetTracker,
    ContentAddressedCache,
    PromptRegistry,
)
from secureflow.llm.base import LLMClient, LLMError
from secureflow.llm.factory import build_patch_llm_client
from secureflow.llm.gemini_client import RateLimitedError
from secureflow.schemas.llm_outputs import PatchReplacement, PatchReview, PatchSuggestion
from secureflow.tools.rescan import rerun_for
from secureflow.utils.logging import get_logger
from secureflow.utils.secret_masker import mask

log = get_logger("agent.patch")

_CONTEXT_LINES = 25


def patch_generation(state: dict) -> dict:
    cfg = Config.model_validate(state.get("config") or {})
    findings = list(state.get("exploitability_results") or [])

    if not findings:
        return {"patch_results": [], "final_findings": []}

    # Lazy import to avoid a circular dependency at module load time:
    # secureflow.orchestrator's __init__ imports the graph which imports
    # agents. Pulling worktree helpers in here keeps that chain clean.
    from secureflow.orchestrator.patch_loop import prune_stale_worktrees

    pr_context = state.get("pr_context") or {}
    repo_path = pr_context.get("repo_path") or "."
    prune_stale_worktrees(repo_path)

    # Decide who gets LLM patch attempts vs. structural skip.
    candidates: list[dict] = []
    finalized_skips: list[dict] = []
    for f in findings:
        if _skip_patch(f):
            finalized_skips.append(_mark_skipped(f))
            continue
        if len(candidates) >= cfg.limits.max_patches_per_pr:
            finalized_skips.append(_mark_status(f, "none", "patch budget exceeded"))
            continue
        candidates.append(f)

    if not candidates:
        log.info(
            "patch: no candidates to attempt",
            extra={"skipped": len(finalized_skips)},
        )
        return {"patch_results": [], "final_findings": finalized_skips}

    cache = ContentAddressedCache(enabled=cfg.llm.cache)
    budget = BudgetTracker(limits=cfg.limits)
    try:
        # Patch-specific chain — see `build_patch_llm_client` docstring for
        # why this is different from the generic `build_llm_client`. When
        # `llm.patch_provider` is unset the call transparently falls
        # back to the standard chain.
        client: LLMClient = build_patch_llm_client(cfg, cache=cache, budget=budget)
    except Exception as e:
        log.info("patch agent: LLM unavailable (%s); skipping generation", e)
        return {
            "patch_results": [],
            "final_findings": finalized_skips + [_mark_status(f, "none", "llm_unavailable") for f in candidates],
            "scanner_errors": {"patch": f"llm_unavailable: {type(e).__name__}"},
        }

    try:
        # v3 tightens output constraints after pre-prod evidence of free
        # OpenRouter models returning multi-language mojibake. Adds:
        # English-only requirement, BAD-example showing the actual
        # failure mode, broader fix-pattern table (IaC + Dockerfile +
        # GHA). v2 stays available for back-compat / A/B testing via
        # `PromptRegistry().get("patch", "v2")`.
        prompt = PromptRegistry().get("patch", "v3")
    except FileNotFoundError as e:
        log.warning("patch agent: prompt missing (%s)", e)
        return {
            "patch_results": [],
            "final_findings": finalized_skips + [_mark_status(f, "none", "prompt_missing") for f in candidates],
            "scanner_errors": {"patch": f"prompt_missing: {e}"},
        }

    # Second-opinion review prompt — loaded lazily inside `_patch_one`
    # via this registry instance so a missing v1 doesn't block the run.
    try:
        review_prompt = PromptRegistry().get("patch_review", "v1")
    except FileNotFoundError:
        review_prompt = None
        log.info("patch_review prompt missing; skipping the LLM review pass")

    workers = max(1, min(cfg.limits.max_patch_concurrency, len(candidates)))
    updated: dict[str, dict] = {f["id"]: _mark_status(dict(f), "none", "pending") for f in candidates}
    rate_limited = False
    errors: list[str] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_id = {
            pool.submit(
                _patch_one,
                client=client, prompt_spec=prompt,
                review_prompt_spec=review_prompt, finding=f,
                repo_path=repo_path, cfg=cfg,
            ): f["id"]
            for f in candidates
        }
        for future in as_completed(future_to_id):
            fid = future_to_id[future]
            if rate_limited:
                future.cancel()
                updated[fid] = _mark_status(updated[fid], "none", "rate_limited_skip")
                continue
            try:
                merged, _ti, _to, _lc = future.result()
                updated[fid] = merged
            except RateLimitedError as e:
                log.warning(
                    "patch: LLM rate-limited; tripping circuit breaker (%s)", e,
                )
                rate_limited = True
                errors.append(f"rate_limited: {e}")
                updated[fid] = _mark_status(updated[fid], "none", "rate_limited")
            except BudgetExceededError as e:
                log.info("patch: budget exceeded (%s); remaining skipped", e)
                errors.append(f"budget_exceeded: {e}")
                updated[fid] = _mark_status(updated[fid], "none", "budget_exceeded")
                break
            except Exception as e:
                log.warning("patch finding %s failed: %s", fid, e)
                errors.append(f"{fid}: {type(e).__name__}")
                updated[fid] = _mark_status(updated[fid], "none", f"error:{type(e).__name__}")

    final_findings = finalized_skips + list(updated.values())
    payload: dict = {
        "patch_results": [
            {
                "finding_id": f["id"],
                "patch_status": f.get("patch_status"),
                "patch_explanation": f.get("patch_explanation"),
                "unified_diff": f.get("patch_unified_diff"),
            }
            for f in updated.values()
        ],
        "final_findings": final_findings,
        # Report the BudgetTracker's actual count, not a per-success
        # accumulator. The client records every HTTP call (including ones
        # whose response failed schema validation and triggered a retry)
        # before raising — so this number reflects real LLM usage while
        # the old accumulator only counted clean successes.
        "budget_used": budget.snapshot(),
        "prompt_versions": {"patch": prompt.prompt_version},
    }
    if errors:
        payload["scanner_errors"] = {"patch": "; ".join(errors)[:300]}

    log.info(
        "patch generation complete",
        extra={
            "verified": sum(1 for f in updated.values() if f.get("patch_status") == "verified"),
            "unverified": sum(1 for f in updated.values() if f.get("patch_status") == "unverified"),
            "conflict": sum(1 for f in updated.values() if f.get("patch_status") == "conflict"),
            "none": sum(1 for f in updated.values() if f.get("patch_status") == "none"),
            "llm_calls": budget.snapshot()["llm_calls"],
        },
    )
    return payload


# ──────────────────────────────────────────────────────────── per-finding ──


def _patch_one(
    *,
    client: LLMClient,
    prompt_spec,
    review_prompt_spec,
    finding: dict,
    repo_path: str,
    cfg: Config,
) -> tuple[dict, int, int, int]:
    """Generate a patch, apply it, rescan, review, and return the merged finding."""
    code_context = _read_context(repo_path, finding)

    user = prompt_spec.render_user(
        finding_id=finding["id"],
        source=finding.get("source", "?"),
        title=mask(finding.get("title") or ""),
        file_path=finding.get("file_path") or "",
        start_line=finding.get("start_line") or 0,
        end_line=finding.get("end_line") or finding.get("start_line") or 0,
        severity=finding.get("severity", "info"),
        cwe=", ".join(finding.get("cwe") or []),
        recommendation=mask(finding.get("recommendation") or "")[:600],
        code_context=mask(code_context)[:3500],
    )

    # `PatchReplacement` (3 required fields) is what we send to the LLM —
    # Ollama's grammar enforcement on Optionals is permissive, so we keep
    # the model-facing schema minimal. We wrap into the richer
    # `PatchSuggestion` here so downstream code keeps its single type.
    result = client.complete(
        system=prompt_spec.system,
        user=user,
        schema=PatchReplacement,
        prompt_version=prompt_spec.prompt_version,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
    )
    llm_calls = 0 if result.cache_hit else 1

    # Gate the patch behind a gibberish sanity check BEFORE we apply it
    # or surface it to the reviewer. Catches the OpenRouter-free-model
    # failure mode where the LLM passed schema validation (non-empty
    # `replacement_code` string) but the contents are multi-language
    # mojibake. See `_looks_like_gibberish` for the heuristic.
    sanity_reason = _looks_like_gibberish(
        result.parsed.replacement_code,
        file_path=finding.get("file_path") or "",
    )
    if sanity_reason:
        log.warning(
            "patch finding %s: rejecting suspected-gibberish replacement_code (%s)",
            finding.get("id"), sanity_reason,
        )
        rejected = dict(finding)
        rejected["patch_status"] = "none"
        rejected["patch_verification_notes"] = (
            f"LLM returned a `replacement_code` that failed the gibberish "
            f"sanity check ({sanity_reason}). Rejected before apply so a "
            "bad patch doesn't end up in the bot comment."
        )
        rejected["prompt_version"] = prompt_spec.prompt_version
        return rejected, result.tokens_in, result.tokens_out, llm_calls

    suggestion = PatchSuggestion(
        finding_id=result.parsed.finding_id,
        patch_type="code",
        unified_diff=None,
        replacement_code=result.parsed.replacement_code,
        explanation=result.parsed.explanation or "",
    )
    merged = _apply_and_verify(finding, suggestion, repo_path, cfg, prompt_spec.prompt_version)

    # Second-opinion LLM review pass. Reads the original lines from disk,
    # the proposed replacement, the rescan verdict — and asks a fresh
    # LLM call: does this fix mitigate the vuln AND match the code
    # context? See `_run_patch_review` for how the verdict folds into
    # patch_status (review can downgrade or upgrade the status).
    tokens_in_total = result.tokens_in
    tokens_out_total = result.tokens_out
    llm_calls_total = llm_calls
    if review_prompt_spec is not None and merged.get("replacement_code"):
        merged, rev_in, rev_out, rev_calls = _run_patch_review(
            client=client,
            review_prompt_spec=review_prompt_spec,
            patched_finding=merged,
            repo_path=repo_path,
            cfg=cfg,
        )
        tokens_in_total += rev_in
        tokens_out_total += rev_out
        llm_calls_total += rev_calls

    return merged, tokens_in_total, tokens_out_total, llm_calls_total


def _apply_and_verify(
    finding: dict,
    suggestion: PatchSuggestion,
    repo_path: str,
    cfg: Config,
    prompt_version: str,
) -> dict:
    """Apply the suggested patch to a temp worktree and re-run the scanner."""
    from secureflow.orchestrator.patch_loop import TempWorktree

    out = dict(finding)
    out["patch_explanation"] = suggestion.explanation
    out["prompt_version"] = prompt_version

    # Resolve the unified diff. Strong models return one directly; smaller
    # models return `replacement_code` and we synthesise the diff from the
    # finding's line range.
    diff_text = suggestion.unified_diff or ""
    replacement_text = (suggestion.replacement_code or "").strip()
    if not diff_text.strip() and replacement_text:
        synthesised = _synthesise_diff_from_replacement(
            finding=finding,
            repo_path=repo_path,
            replacement_code=replacement_text,
        )
        if synthesised is None:
            out["patch_status"] = "none"
            out["patch_verification_notes"] = (
                "LLM returned replacement_code but the file/line range "
                "couldn't be resolved to synthesise a diff."
            )
            return out
        diff_text = synthesised
        out["patch_synthesised_from_replacement"] = True
    # Persist the raw replacement (no diff markers) so the markdown report
    # can render a GitHub `suggestion` block.
    if replacement_text:
        out["replacement_code"] = replacement_text

    if suggestion.patch_type == "manual" or not diff_text.strip():
        out["patch_status"] = "suggested" if suggestion.patch_type == "manual" else "none"
        out["patch_verification_notes"] = (
            "LLM declined to auto-patch; manual review required."
            if suggestion.patch_type == "manual"
            else "LLM returned no diff."
        )
        return out

    out["patch_unified_diff"] = diff_text
    # Rebuild a `PatchSuggestion`-ish shim only for downstream code paths
    # that still read `suggestion.unified_diff`. We re-use the local var.
    suggestion = suggestion.model_copy(update={"unified_diff": diff_text})
    with TempWorktree(repo_path) as worktree:
        if not worktree.apply_patch(suggestion.unified_diff):
            out["patch_status"] = "conflict"
            out["patch_verification_notes"] = (
                "Patch did not apply cleanly to a temp copy of the working tree."
            )
            return out

        result = rerun_for(out, worktree_root=worktree.root)
        if result.error:
            out["patch_status"] = "unverified"
            out["patch_verification_notes"] = (
                f"Patch applied but scanner re-run failed: {result.error}"
            )
        elif result.finding_still_present:
            out["patch_status"] = "unverified"
            out["patch_verification_notes"] = (
                "Patch applied but the originating scanner still reports this finding."
            )
        else:
            out["patch_status"] = "verified"
            out["patch_verification_notes"] = (
                "Patch applied to a temp working tree; the originating scanner no longer reports this finding."
            )
    return out


# ──────────────────────────────────────────────────────────── helpers ──


def _synthesise_diff_from_replacement(
    *,
    finding: dict,
    repo_path: str,
    replacement_code: str,
) -> str | None:
    """Build a unified diff from `replacement_code` + the finding's line range.

    Small local models reliably emit the secure replacement code but fail
    to format unified diffs correctly. We deterministically construct the
    diff so they don't have to.

    Returns the diff string, or `None` if the file/line range can't be
    resolved (in which case the caller marks the patch unverified).
    """
    file_path = finding.get("file_path")
    start_line: int | None = finding.get("start_line")
    end_line: int | None = finding.get("end_line") or start_line
    if not file_path or not start_line or not end_line:
        return None

    # Scanners report `file_path` relative to whatever directory they ran in.
    # Try the most likely bases in order: the repo_path passed in, the
    # current working directory, and the path interpreted as already
    # absolute. This makes synthesis robust to whether the scan was
    # `--repo .` (file_path is repo-relative) or `--repo subdir/` (file_path
    # may be cwd-relative because that's how semgrep reports it).
    candidates = [
        Path(repo_path) / file_path,
        Path.cwd() / file_path,
        Path(file_path),
    ]
    target: Path | None = next(
        (p for p in candidates if p.is_file()), None,
    )
    if target is None:
        return None

    try:
        original_text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None

    original_lines = original_text.splitlines(keepends=True)
    # Clamp to the file length so an off-by-one from the model/scanner
    # doesn't break diff generation.
    a = max(0, start_line - 1)
    b = min(len(original_lines), end_line)
    if a >= b:
        return None

    # Preserve leading indentation: if the model omitted it, copy the
    # indentation of the first replaced line so the result still parses
    # at the same block level.
    leading_ws = ""
    first_orig = original_lines[a]
    stripped = first_orig.lstrip()
    if first_orig != stripped:
        leading_ws = first_orig[: len(first_orig) - len(stripped)]

    replacement = replacement_code.rstrip("\n").splitlines() or [""]
    if leading_ws and not replacement[0].startswith(leading_ws):
        replacement = [
            (leading_ws + line) if line.strip() else line
            for line in replacement
        ]
    # Re-attach trailing newlines so the diff has matching line terminators.
    replacement_lines = [line + "\n" for line in replacement]
    # If the original file's final replaced line had no trailing newline
    # (e.g., last line of a no-final-newline file), strip our last newline.
    if not original_lines[b - 1].endswith("\n"):
        replacement_lines[-1] = replacement_lines[-1].rstrip("\n")

    new_lines = original_lines[:a] + replacement_lines + original_lines[b:]
    # `git apply` runs inside the temp worktree, which is a copy of
    # `repo_path`. So the path inside the diff must be RELATIVE to the
    # worktree root (== relative to the resolved repo_path), not the
    # absolute or cwd-rooted path we used to read the file. Without this,
    # the apply fails with "No such file or directory" on the rebase
    # subtree.
    try:
        diff_path_obj = target.resolve().relative_to(Path(repo_path).resolve())
    except ValueError:
        # Target lives outside repo_path — fall back to the raw file_path
        # the scanner provided, normalised to forward slashes.
        diff_path_obj = Path(file_path)
    diff_path = str(diff_path_obj).replace("\\", "/")
    diff = difflib.unified_diff(
        original_lines,
        new_lines,
        fromfile=f"a/{diff_path}",
        tofile=f"b/{diff_path}",
        n=3,
    )
    return "".join(diff)


def _skip_patch(finding: dict) -> bool:
    """Findings that don't go through LLM patch generation."""
    src = finding.get("source")
    # AI-discovered findings can't be auto-verified; mark structurally.
    if src == "ai_discovery":
        return True
    # False-positives shouldn't get patches.
    if finding.get("false_positive"):
        return True
    # Info/low severity isn't worth the token spend.
    if finding.get("severity") in {"info", "low"}:
        return True
    return False


def _mark_skipped(finding: dict) -> dict:
    """Apply the right patch_status to a finding we intentionally skip."""
    out = dict(finding)
    src = out.get("source")
    if src == "ai_discovery":
        out["patch_status"] = "not_applicable"
        out["patch_verification_notes"] = (
            "AI-discovered findings cannot be auto-verified by re-running a scanner; "
            "please review the recommendation manually."
        )
    elif out.get("false_positive"):
        out["patch_status"] = "none"
        out["patch_verification_notes"] = "Marked as false positive; no patch needed."
    else:
        out["patch_status"] = "none"
        out["patch_verification_notes"] = "Low-severity finding; no patch attempted."
    return out


def _mark_status(finding: dict, status: str, note: str) -> dict:
    out = dict(finding)
    out["patch_status"] = status
    out["patch_verification_notes"] = note
    return out


def _read_context(repo_path: str, finding: dict) -> str:
    """Read N lines around the finding's location from disk."""
    file_path = finding.get("file_path")
    start_line: int | None = finding.get("start_line")
    if not file_path or not start_line:
        return finding.get("evidence") or ""
    full = Path(repo_path) / file_path
    if not full.exists() or not full.is_file():
        return finding.get("evidence") or ""
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return finding.get("evidence") or ""
    end_line = finding.get("end_line") or start_line
    a = max(0, start_line - 1 - _CONTEXT_LINES)
    b = min(len(lines), end_line + _CONTEXT_LINES)
    width = len(str(b))
    rendered: list[str] = []
    for i in range(a, b):
        marker = ">>" if (start_line - 1) <= i <= (end_line - 1) else "  "
        rendered.append(f"{marker} {str(i + 1).rjust(width)} | {lines[i]}")
    return "\n".join(rendered)


# ─────────────────────────────────────────────── patch review pass ──
# Maps the cross-product of (scanner rescan result, LLM review verdict)
# to the final `patch_status`. Rules:
#
#   scanner=verified + review approves      → keep verified (both agree)
#   scanner=verified + review rejects       → DOWNGRADE to unverified
#       (review spotted something scanner missed — e.g. mojibake that
#       happened not to match the rule's regex)
#   scanner=unverified + review approves    → keep unverified
#       (scanner-rerun is the ground truth for scanner-detected
#       findings; we just record the disagreement in notes so a human
#       can decide whether the rule is overly broad)
#   scanner=unverified + review rejects     → keep unverified (both
#       signals agree the patch is bad)
#   scanner=conflict + any review           → keep conflict — the patch
#       didn't apply; review is irrelevant
#   scanner=not_applicable + review approves → UPGRADE to verified
#       (no scanner to rerun for AI-only findings; review is the only
#       signal we have)
#   scanner=not_applicable + review rejects → unverified
#   review="uncertain" → leave status alone, record the verdict
#
# Design choice: only `not_applicable` gets upgraded by an approve. We
# do NOT promote scanner-flagged-still-present to verified just because
# the LLM thinks the patch looks good — the scanner is the higher-
# fidelity signal for the questions it can answer.

# Cap how much content we feed the review prompt so the run stays cheap.
_REVIEW_ORIGINAL_CAP = 2000
_REVIEW_REPLACEMENT_CAP = 2000


def _run_patch_review(
    *,
    client: LLMClient,
    review_prompt_spec,
    patched_finding: dict,
    repo_path: str,
    cfg: Config,
) -> tuple[dict, int, int, int]:
    """Run the second-opinion LLM review on a patched finding.

    Returns (updated_finding, tokens_in, tokens_out, llm_calls). All
    failures are non-fatal — review errors leave `patch_status`
    unchanged and add a note. The point of review is to *strengthen*
    confidence, not to introduce a new failure path.
    """
    fid = patched_finding.get("id") or ""
    replacement = (patched_finding.get("replacement_code") or "").strip()
    if not replacement:
        return patched_finding, 0, 0, 0
    rescan_status = patched_finding.get("patch_status") or "none"
    # `conflict` means the patch didn't apply cleanly. Review can't
    # rescue that — skip.
    if rescan_status == "conflict":
        return patched_finding, 0, 0, 0
    # `none` means we already rejected the patch (gibberish sanity, etc.).
    # Don't burn an LLM call to confirm something we already know is bad.
    if rescan_status == "none":
        return patched_finding, 0, 0, 0

    original_code = _read_replaced_lines(
        repo_path=repo_path,
        file_path=patched_finding.get("file_path") or "",
        start_line=patched_finding.get("start_line"),
        end_line=patched_finding.get("end_line"),
    )
    rescan_summary = patched_finding.get("patch_verification_notes") or "(no rescan summary)"

    user = review_prompt_spec.render_user(
        finding_id=fid,
        source=patched_finding.get("source") or "?",
        title=mask(patched_finding.get("title") or ""),
        file_path=patched_finding.get("file_path") or "",
        start_line=patched_finding.get("start_line") or 0,
        end_line=patched_finding.get("end_line") or patched_finding.get("start_line") or 0,
        severity=patched_finding.get("severity") or "info",
        cwe=", ".join(patched_finding.get("cwe") or []),
        recommendation=mask(patched_finding.get("recommendation") or "")[:600],
        original_code=mask(original_code)[:_REVIEW_ORIGINAL_CAP],
        replacement_code=mask(replacement)[:_REVIEW_REPLACEMENT_CAP],
        patch_explanation=mask(patched_finding.get("patch_explanation") or "")[:400],
        rescan_summary=rescan_summary[:300],
    )

    try:
        result = client.complete(
            system=review_prompt_spec.system,
            user=user,
            schema=PatchReview,
            prompt_version=review_prompt_spec.prompt_version,
            temperature=cfg.llm.temperature,
            max_tokens=cfg.llm.max_tokens,
        )
    except (LLMError, RateLimitedError) as e:
        # Review couldn't run — keep the original rescan-based status,
        # add a note so the reviewer knows the second-opinion didn't fire.
        notes = patched_finding.get("patch_verification_notes") or ""
        appended = (notes + " | " if notes else "") + f"review skipped: {type(e).__name__}"
        out = dict(patched_finding)
        out["patch_verification_notes"] = appended[:500]
        log.info("patch review for %s skipped: %s", fid, type(e).__name__)
        return out, 0, 0, 0
    except Exception as e:  # noqa: BLE001 — non-fatal
        log.warning("patch review for %s raised %s; keeping rescan-based status", fid, type(e).__name__)
        return patched_finding, 0, 0, 0

    review = result.parsed
    return (
        _fold_review_into_status(patched_finding, review),
        result.tokens_in,
        result.tokens_out,
        0 if result.cache_hit else 1,
    )


def _fold_review_into_status(finding: dict, review: PatchReview) -> dict:
    """Combine the rescan-based status with the LLM review verdict.

    See the module-level mapping comment above `_run_patch_review` for
    the rules. The function never raises; it just rewrites
    `patch_status` and appends to `patch_verification_notes`.
    """
    out = dict(finding)
    rescan_status = out.get("patch_status") or "none"
    verdict = review.verdict
    base_notes = out.get("patch_verification_notes") or ""
    concerns_text = "; ".join(c.strip() for c in (review.concerns or []) if c and c.strip())[:300]

    def _append_review_note(verdict_label: str) -> str:
        bits = [base_notes] if base_notes else []
        bits.append(
            f"review[{verdict_label}] conf={review.confidence:.2f}"
            + (f" concerns={concerns_text}" if concerns_text else "")
        )
        return " | ".join(bits)[:500]

    if verdict == "uncertain":
        # Don't change the status; just record the second-opinion.
        out["patch_verification_notes"] = _append_review_note("uncertain")
        out["patch_review_verdict"] = "uncertain"
        return out

    out["patch_review_verdict"] = verdict
    out["patch_review_confidence"] = round(float(review.confidence or 0.0), 2)
    out["patch_review_concerns"] = list(review.concerns or [])

    if verdict == "approve":
        # ONLY promote when the scanner couldn't weigh in (AI-only
        # findings) — that's the case where review is the best signal
        # we'll get. For scanner-detected findings, the scanner stays
        # the ground truth.
        if rescan_status == "not_applicable" and review.confidence >= 0.7:
            out["patch_status"] = "verified"
            out["patch_verification_notes"] = _append_review_note(
                "approve (upgraded from not_applicable)"
            )
        else:
            out["patch_verification_notes"] = _append_review_note("approve")
        return out

    # verdict == "reject"
    # Downgrade verified → unverified so the reviewer treats it as
    # needs-human-eyes. Keep the patch text on the finding so the
    # bot comment still shows what the LLM proposed (with the
    # concerns visible in the notes).
    if rescan_status == "verified":
        out["patch_status"] = "unverified"
        out["patch_verification_notes"] = _append_review_note(
            "reject (downgraded from verified)"
        )
    elif rescan_status == "not_applicable":
        # AI-only finding the review rejects: treat as unverified so
        # the bot comment doesn't trumpet a bad fix.
        out["patch_status"] = "unverified"
        out["patch_verification_notes"] = _append_review_note("reject")
    else:
        # Already `unverified` — keep it; just record the agreement.
        out["patch_verification_notes"] = _append_review_note("reject")
    return out


def _read_replaced_lines(
    *,
    repo_path: str,
    file_path: str,
    start_line: int | None,
    end_line: int | None,
) -> str:
    """Read the exact source lines being replaced, for the review prompt."""
    if not file_path or not start_line:
        return ""
    candidates = [
        Path(repo_path) / file_path,
        Path.cwd() / file_path,
        Path(file_path),
    ]
    target = next((p for p in candidates if p.is_file()), None)
    if target is None:
        return ""
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    a = max(0, int(start_line) - 1)
    b = min(len(lines), int(end_line or start_line))
    return "\n".join(lines[a:b])


# ───────────────────────────────────────────── gibberish sanity check ──
# Concrete failure mode from pre-prod: OpenRouter's free
# `deepseek-v4-flash:free` returned 1,092 completion tokens of
# multi-language mojibake when asked for a `PatchReplacement` JSON. The
# response passed pydantic validation (non-empty `replacement_code`
# string), but the contents were Chinese / Greek / Cyrillic / math
# symbols / fragments of unrelated prose. The orchestrator dutifully
# applied that to the file, rescanned (which happened to not match the
# rule because the rule's regex didn't match gibberish either), and
# claimed the patch was "verified." Net result: a `replacement_code`
# block of garbage shown to the reviewer as the recommended fix.
#
# This check rejects clearly-bad outputs BEFORE we apply them. The
# heuristic is intentionally permissive — false positives here mean we
# drop a real-but-unusual patch; false negatives mean we ship garbage.
# Tuned for the second to be much worse than the first.

# Files whose languages we recognise. Patches for files outside this
# set still get the cross-cutting checks (non-ASCII ratio, placeholder
# strings) but skip the language-specific keyword check.
_LANG_KEYWORDS: dict[str, frozenset[str]] = {
    # Python — common syntactic tokens that ~any non-trivial patch contains.
    ".py": frozenset({
        "def", "return", "if", "import", "from", "class", "for", "while",
        "with", "try", "except", "raise", "pass", "and", "or", "not",
        "=", "(", ")", ":",
    }),
    # JS / TS — overlap with Python on operators, distinct keywords.
    ".js": frozenset({
        "function", "const", "let", "var", "return", "if", "else",
        "import", "require", "class", "for", "while", "throw", "try",
        "=>", "{", "}", "(", ")", ";",
    }),
    ".ts": frozenset({
        "function", "const", "let", "var", "return", "if", "else",
        "import", "class", "interface", "type", "for", "while",
        "=>", "{", "}", "(", ")", ";",
    }),
    ".tsx": frozenset({
        "function", "const", "let", "return", "import", "=>", "{", "}",
    }),
    ".jsx": frozenset({
        "function", "const", "let", "return", "import", "=>", "{", "}",
    }),
    # Go — distinct syntax tokens.
    ".go": frozenset({"func", "return", "if", "import", "package", "var", ":=", "{", "}"}),
    # Terraform / HCL — what most IaC patches will be.
    ".tf": frozenset({"resource", "data", "variable", "output", "=", "{", "}"}),
    ".tfvars": frozenset({"=", "{", "}"}),
    # YAML (Kubernetes, GitHub Actions, etc.) — content-light, so we
    # accept any keyword from `: -` indentation pattern.
    ".yml": frozenset({":", "-"}),
    ".yaml": frozenset({":", "-"}),
    # Dockerfile — uppercase directives.
    ".dockerfile": frozenset({"FROM", "RUN", "COPY", "ADD", "USER", "CMD", "ENTRYPOINT", "ENV", "EXPOSE", "ARG"}),
    # JSON (IAM policies, etc.).
    ".json": frozenset({":", "{", "}", "[", "]", "\""}),
    # Ruby / Java / C# — generic Python-shaped tokens cover most.
    ".rb": frozenset({"def", "end", "if", "do", "return", "=", "{", "}"}),
    ".java": frozenset({"public", "private", "class", "return", "if", "import", "{", "}", "(", ")", ";"}),
    ".cs": frozenset({"public", "private", "class", "return", "if", "using", "namespace", "{", "}", "(", ")", ";"}),
    ".php": frozenset({"function", "return", "if", "else", "$", "{", "}", "(", ")", ";"}),
}

_PLACEHOLDER_PATTERNS = (
    "<your_fix_here>", "<the new code", "<fix here>", "<replacement>",
    "TODO: implement", "TODO: replace",
)


def _looks_like_gibberish(replacement_code: str, *, file_path: str) -> str | None:
    """Heuristic: return a short reason string when `replacement_code`
    looks like mojibake/placeholder garbage, else None.

    Three layered checks:
      1. Reject literal placeholder strings (`<your_fix_here>` etc.) —
         the model "answered" without producing real code.
      2. Reject when the non-ASCII printable ratio exceeds ~30%. Real
         code in any language we target is ~98% ASCII. Heavy non-ASCII
         is the mojibake signature.
      3. For known file extensions, require at least ONE language-
         appropriate keyword/operator in the output. A patch with zero
         recognisable syntax tokens for the target language is almost
         certainly wrong, regardless of how it scans visually.

    Returns the reason string on rejection so logs / patch_verification_
    notes can carry the specific failure mode.
    """
    body = (replacement_code or "").strip()
    if not body:
        # The pydantic min_length should prevent this, but defence-in-depth.
        return "empty replacement_code"

    low = body.lower()
    for needle in _PLACEHOLDER_PATTERNS:
        if needle.lower() in low:
            return f"contains placeholder text: {needle!r}"

    # Count "informative" chars (non-whitespace) for the ratio check.
    informative = [c for c in body if not c.isspace()]
    if not informative:
        return "no non-whitespace content"
    non_ascii = sum(1 for c in informative if ord(c) > 127)
    ratio = non_ascii / len(informative)
    # 0.30 chosen empirically: a Chinese-character salad gets ~0.8+, a
    # block of English code with a few unicode arrows gets <0.10. The
    # rare legitimate non-ASCII identifier (e.g. unicode in a Python 3
    # variable name) sits around 0.10–0.20.
    if ratio > 0.30:
        return f"non-ASCII ratio {ratio:.0%} suggests mojibake"

    # Language-specific keyword check.
    suffix = _file_suffix_for_check(file_path)
    keywords = _LANG_KEYWORDS.get(suffix)
    if keywords is not None:
        # Case-sensitive for Dockerfile (uppercase directives matter);
        # case-insensitive elsewhere.
        haystack = body if suffix == ".dockerfile" else body.lower()
        needles = keywords if suffix == ".dockerfile" else {k.lower() for k in keywords}
        if not any(n in haystack for n in needles):
            return f"no recognisable {suffix} keyword/operator in replacement"

    return None


def _file_suffix_for_check(file_path: str) -> str:
    """Return the file suffix used to look up `_LANG_KEYWORDS`.

    Dockerfile has no suffix; we map it to a synthetic `.dockerfile` key
    so the same table lookup works.
    """
    if not file_path:
        return ""
    name = file_path.lower().split("/")[-1].split("\\")[-1]
    if name == "dockerfile" or name.startswith("dockerfile."):
        return ".dockerfile"
    dot = name.rfind(".")
    if dot < 0:
        return ""
    return name[dot:]
