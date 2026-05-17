# Design 03 — Patch Validation Loop

> Detailed spec for the patch-validation behavior inside `patch_generation` (orchestrator node) and `secureflow.agents.patch_agent`. Companion to `ARCHITECTURE.md §2.5`, `design/02_orchestrator.md §4.10`.
>
> **Why this exists separately.** Note: the patch-validation loop is being promoted from "optional" to a core differentiator. It deserves its own spec because the value of the whole project hinges on it: a patch the system re-scanned and confirmed clean is *qualitatively* more credible than a raw LLM patch suggestion.

## 1. Goal

For every scanner-detected finding, produce a patch that has been **applied + re-scanned + confirmed to remove the finding**. Report unverified patches as such so reviewers know which suggestions to trust.

For AI-only findings (which can't be re-scanned the same way), produce a patch with `patch_status: not_applicable` and ship it as a *suggestion* in the report. Be honest about the difference.

## 2. Status taxonomy

```python
class PatchStatus(str, Enum):
    NONE = "none"                       # No patch produced (intentional skip)
    SUGGESTED = "suggested"             # Patch produced, not yet validated
    VERIFIED = "verified"               # Patch applied; originating scanner no longer reports finding
    UNVERIFIED = "unverified"           # Patch applied; scanner still flags finding (or scanner errored)
    NOT_APPLICABLE = "not_applicable"   # AI-only finding; cannot be scanner-validated
    CONFLICT = "conflict"               # Patch failed to apply cleanly to current tree
```

Only `verified` patches appear above the fold in the PR comment. `suggested` / `unverified` patches appear in a collapsed section with explicit caveats.

## 3. Flow

```
For each finding F in final_findings:
    if F.source == "ai_discovery":
        patch = generate_patch_via_llm(F)
        patch.status = NOT_APPLICABLE
        attach(F, patch); continue

    if F.severity in {"info", "low"} and not config.patch.generate_for_low:
        attach(F, patch=None); continue   # skip low-value findings

    patch = generate_patch_via_llm(F)
    if patch is None:
        attach(F, patch_status=NONE); continue

    with TempWorktree(repo) as wt:
        if not wt.apply_patch(patch.unified_diff):
            patch.status = CONFLICT
            attach(F, patch); continue

        rerun_result = rerun_originating_scanner(wt, F)
        if rerun_result.error:
            patch.status = UNVERIFIED
            patch.unverified_reason = rerun_result.error
        elif finding_still_present(rerun_result.findings, F):
            patch.status = UNVERIFIED
        else:
            patch.status = VERIFIED
    attach(F, patch)
```

## 4. Temp worktree

The fastest way to apply-and-rescan without touching the real working tree is `git worktree add` against the same repo.

```python
class TempWorktree:
    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="secureflow-patch-")
        subprocess.run(["git", "worktree", "add", "--detach", self.path, "HEAD"], check=True)
        return self
    def __exit__(self, *exc):
        subprocess.run(["git", "worktree", "remove", "--force", self.path], check=False)
        shutil.rmtree(self.path, ignore_errors=True)
    def apply_patch(self, unified_diff: str) -> bool:
        try:
            subprocess.run(["git", "apply", "--index"], input=unified_diff.encode(),
                           cwd=self.path, check=True, timeout=15)
            return True
        except subprocess.CalledProcessError:
            return False
```

Why `git worktree add` rather than `cp -r`:
- Sub-second on most repos (only checks out a working tree pointer).
- Shares object database with the main repo — no disk-space bloat.
- `git worktree remove` cleans up reliably.

**Cleanup guarantee:** `__exit__` runs even on exception. Stale worktrees from prior crashed runs are cleaned at orchestrator startup via `git worktree prune`.

## 5. Re-running the originating scanner

Only the *originating* scanner re-runs — not the full scanner suite — per `ARCHITECTURE.md §8 Q7` (cost bound).

```python
RESCAN_MAP = {
    "semgrep":  rerun_semgrep_on_files,
    "gitleaks": rerun_gitleaks_on_files,
    "grype":    rerun_grype_on_repo,    # grype runs on the whole repo, not file-scoped
    "bandit":   rerun_bandit_on_files,
}
```

For file-scoped scanners (Semgrep, Gitleaks, Bandit), the re-run is limited to the patched file → fast (~1-3 seconds).

For Grype (whole-repo by nature), the re-run is the full dependency scan → slow (~10-30 seconds). For dependency findings the patch is almost always a version bump in a manifest file; we still run full Grype to verify the bump resolved the CVE.

Per-scanner re-run has its own timeout (default 60s) and falls back to `UNVERIFIED` with reason `rescan_timeout`.

## 6. "Finding still present" check

The originating finding has a stable ID (see `design/05_schemas_and_finding_ids.md`). After re-scan, we look for that same ID in the new results.

But IDs are based on (source, rule_id, file_path, normalized_line_signature, code_fingerprint). After a patch:
- The code fingerprint changes → ID changes → naive ID-match would say "finding gone." That's correct in most cases.
- *But* the patch might just rename a variable while keeping the vulnerability. The scanner would report a new finding with a different ID — and the user would believe the original was fixed.

Defense: compare the new findings list against the original by (source, rule_id, file_path, **fuzzy line range**). If a finding with the same rule on the same file within ±5 lines of the original exists, mark `UNVERIFIED`. Only `VERIFIED` if no such match.

## 7. Concurrency

- Per finding: independent worktree (each gets its own `tempfile.mkdtemp`).
- Max parallel patch validations: `limits.max_patch_concurrency` (default 2 — disk + scanner CPU intensive).
- Within one validation: scanner re-run is single-threaded.

## 8. Failure modes

| Failure | Status | User-visible message |
|---|---|---|
| LLM produced no patch | `NONE` | "No patch was generated for this finding." |
| Patch failed to apply | `CONFLICT` | "The suggested patch did not apply cleanly; manual review needed." |
| Scanner errored during re-run | `UNVERIFIED` (reason logged) | "Patch was applied but verification could not run — please confirm manually." |
| Finding still present after patch | `UNVERIFIED` | "Patch was applied but the scanner still reports the issue." |
| Patch removes finding | `VERIFIED` | "✅ Verified — applied to a temp copy and the scanner no longer flags this issue." |
| AI-only finding | `NOT_APPLICABLE` | "Suggested fix — please review manually (AI-discovered findings can't be auto-verified)." |

## 9. Reporting

In the Markdown report and PR comment:
- **Top section** lists `VERIFIED` patches as confidently-attached suggestions.
- **Collapsed section** lists `SUGGESTED` / `UNVERIFIED` / `CONFLICT` patches with explicit caveat lines.
- **AI suggestions section** lists `NOT_APPLICABLE` patches.
- Risk score (plan §18) gets a small bonus reduction for findings with `VERIFIED` patches available, signaling that a clear fix exists.

## 10. Cost / time budget

Estimated cost per patch validation:
- LLM call: ~500-2000 tokens out + ~1500-4000 tokens in.
- Temp worktree: ~100ms.
- Scanner re-run: 1-3s (file-scoped) or 10-30s (Grype).

For a PR with 5 findings, total added time: ~15-60 seconds. Cap via `limits.max_patches_per_pr` (default 10). When the cap is hit, the remaining findings get `NONE` with reason "patch budget exceeded".

## 11. File layout

```
secureflow/agents/patch_agent.py        # LLM call + orchestration
secureflow/orchestrator/patch_loop.py   # TempWorktree, rescan dispatcher
secureflow/tools/rescan.py              # per-scanner rerun helpers
```

## 12. Acceptance criteria

- [ ] `TempWorktree` context manager creates and cleans up a git worktree reliably (including on exception).
- [ ] Fixture: a SQLi finding gets a parameterized-query patch, applies cleanly, Semgrep re-run shows no finding → `VERIFIED`.
- [ ] Fixture: a hardcoded secret gets an env-var patch, applies, Gitleaks re-run clean → `VERIFIED`.
- [ ] Fixture: a deliberately bad patch (does nothing) → `UNVERIFIED` with finding still present.
- [ ] Fixture: a patch with stale base (conflict) → `CONFLICT`.
- [ ] AI-only finding → always `NOT_APPLICABLE` with patch still produced for manual review.
- [ ] Concurrent validation of 3 findings does not corrupt the main working tree (verified by post-condition: `git status` clean).
- [ ] Aggregate validation time on a 5-finding fixture < 90s (Semgrep-only) / < 180s (with Grype).

## 13. Open questions

- **Q-PATCH-1:** When the patch is a dependency version bump, should we also try to *resolve* the upgrade (run `pip install`, check for resolver errors)? Recommendation: v1 just verifies via Grype on the manifest; v2 can add resolver checks for popular package managers.
- **Q-PATCH-2:** Should `VERIFIED` patches be auto-suggested as a "Apply this patch" GitHub PR review action? Recommendation: no for v1 — human-in-the-loop is a hard requirement (plan §15.4). Add as opt-in stretch feature.
- **Q-PATCH-3:** What about multi-finding patches (one patch fixes 2 findings at once)? Recommendation: in v1, patches are 1-to-1 with findings; if the same code change resolves multiple, the second finding's patch will trivially `VERIFIED` because re-scan won't find it. Accept the duplicate work; collapse in the report.
