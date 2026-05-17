# SecureFlow AI — Design Brief

A two-page architecture summary for reviewer onboarding. For component-level detail see [`ARCHITECTURE.md`](../ARCHITECTURE.md).

---

## 1. Problem

A pull-request reviewer needs to know two things about every diff: **is there a security bug**, and **how serious is it?** Existing tooling answers the first question well (Semgrep, Gitleaks, Grype, CodeQL) and the second question badly — scanners produce a wall of low-confidence findings; humans triage; bugs ship. LLMs can reason about exploitability but hallucinate, follow injected instructions, and sometimes downgrade obvious vulnerabilities.

**SecureFlow's thesis:** the right answer is a **hybrid** — deterministic scanners for recall, LLMs for context-aware exploitability and patches, and a **pure-Python policy engine** that decides PASS/WARN/FAIL based on rules the LLM cannot override. Decisions must be correct *even when the LLM is unavailable*.

---

## 2. Pipeline

```
PR event
   │
   ▼
context_agent  ──┬─►  semgrep      ──┐
                 ├─►  gitleaks     ──┤
                 ├─►  grype        ──┤
                 └─►  ai_discovery ──┤   (LLM)
                                    │
                                    ▼
                               normalize  ←─ taint-floor (deterministic)
                                    │       reachability  hint
                                    │       diff-line filter
                                    ▼
                              threat_map (CWE / OWASP / ATT&CK)
                                    │
                                    ▼
                              enrichment (OSV / CVSS / NVD)
                                    │
                                    ▼
                              exploitability  (LLM — second opinion)
                                    │
                                    ▼
                              patch_agent  (LLM — apply + rescan)
                                    │
                                    ▼
                              decide  (pure-Python policy)
                                    │
                                    ▼
              JSON · Markdown · SARIF · PR comment · run_telemetry.json
```

Three nodes are LLM-using (highlighted yellow in the README diagram); everything else is deterministic Python. Every LLM call is cached (content-addressed), budget-capped, and Pydantic-validated.

---

## 3. Layered guardrails

The architecture has five **independent** guardrails. Each one alone is insufficient; together they produce a system that fails safe.

| # | Guardrail | Failure it stops | Where |
|---|---|---|---|
| 1 | **Pure-Python policy engine** | LLM hallucinating a decision | `policy/policy_engine.py` |
| 2 | **Pydantic-validated structured output** | LLM returning unparseable text | every `LLMClient.complete()` |
| 3 | **Prompt-injection defense in system prompt** | Code comments coercing the LLM | `llm/prompts/*/v1.yaml` |
| 4 | **Deterministic taint-floor** | LLM under-rating clear sinks | `agents/normalizer.py` |
| 5 | **Budget cap + visible banner** | LLM truncated mid-PR going unnoticed | `llm/budget.py` + `reporting/markdown_report.py` |

Guardrails 4 and 5 are the load-bearing ones for "LLM is down, system still correct":

- **Taint floor** — when a scanner-medium SAST finding lives near a known taint source (`request.args`, `r.URL.Query()`, `$_GET`, `params[:`, etc.) and matches a known sink rule (SQLi, command-injection, XXE, SSRF, path-traversal, XSS), floor confidence at 0.7. The policy engine then promotes it to FAIL on its own. Crucial finding: when this fires, it must **override** the path-based unreachable-cap; see "trade-offs" below.
- **Banner** — when LLM agents skip due to budget, rate-limit, or missing credentials, render a `[!WARNING]` callout above the decision badge. Reviewers see "this verdict is scanner-only" before they read the verdict.

---

## 4. LLM strategy: provider-agnostic chain

Every LLM call goes through an `LLMClient` interface with five concrete implementations (DeepSeek, Gemini, Groq, OpenRouter, Ollama). Each handles its own cache lookup, schema validation, retry, and rate-limit cooldown. A **`ChainLLMClient`** wraps a list of providers and fails over on rate-limit, auth, or persistent schema-validation errors. Validation failures are treated as transient because a model that cannot follow our JSON schema is a model problem, not a prompt problem — the next provider may handle it.

Typical config (strongest-first):

```yaml
llm:
  provider: deepseek
  fallback_providers: [gemini, groq, openrouter]
limits:
  max_llm_concurrency: 1   # serial calls — no burst-tripping per-minute caps
```

This composes three free-tier daily budgets (~200 + ~6000 RPD + ~50 RPD without OpenRouter credits) and survives any single provider being temporarily down. Serial execution costs 5–15s of wall-clock per PR and eliminates the bursty-failure mode entirely.

---

## 5. What fails when the LLM fails

This is the most important design property and the hardest one to demonstrate without live evidence. The committed eval at [`reports/eval_xlang_live.md`](../reports/eval_xlang_live.md) shows: a cross-language PR with three vulnerable files (Go SQLi, Java XXE, Ruby cmdi) reaches **decision = FAIL** even when every LLM agent rate-limits. The deterministic taint-floor lifts confidence on the clear sinks; the policy engine promotes them; the banner tells the reviewer the LLM-uplift step didn't happen, so AI-discovered logic flaws may be missing.

**Decision quality is bounded below by the deterministic stack, not by LLM availability.** That's the engineering claim that distinguishes SecureFlow from pure-LLM AppSec tools.

---

## 6. Trade-offs explicitly chosen

| Decision | Alternative | Why we picked this |
|---|---|---|
| LangGraph state machine | Plain Python function | Parallel scanner fan-out + conditional routing + typed state with reducers |
| Semgrep `auto` config | CodeQL | License-free, runs in private repos without GHAS, multi-language |
| Schema-mode JSON | Free-form prompt → regex parse | Validates the contract at the API boundary; corrective retry on schema fail |
| Re-run **originating scanner only** for patch verification | Re-run full suite | 3× wall-clock savings; the originating scanner is the most reliable judge |
| Floor lifts to 0.7, not 1.0 | Higher floor | Lets the LLM downgrade if it has *more* evidence; the floor is a floor, not a ceiling |
| `examples/` is "unreachable" by default | Treat every dir as runtime | Stops the project's own intentional fixtures from FAILing the project's own CI. The taint-floor bypass uses `confidence >= 0.7` as the signal to override |
| 1 LLM call at a time | Concurrent calls | Free-tier per-minute caps trip on bursts; serial costs 5–15s, saves the entire LLM tier |
| Cross-provider chain | Single provider with retry | Each free-tier daily quota is independent; chain compounds the headroom |
| Bot comment **edit**, not append | Append a new comment per push | PR conversations stay readable; the bot doesn't spam |

---

## 7. Out of scope (intentionally)

- **Multi-file data-flow analysis** — current reachability is path-based + one-hop. Real call-graph analysis is a v2 win.
- **Custom-rule authoring** — users get whatever `semgrep auto` provides. Custom Semgrep rules are a deployment concern, not a SecureFlow concern.
- **Auto-merge / auto-close** — by design. SecureFlow signals; humans decide.
- **Build-time integration** — SecureFlow is a *review* tool, not a *compile* tool. SAST belongs at the IDE / pre-commit / PR layer; runtime defense belongs elsewhere.
- **A custom LLM** — we are model-agnostic. The right model is whatever the user has a key for.

---

## 8. What I'd build next

Ranked by ROI (not in current scope):

1. **One-hop caller reachability** via tree-sitter — bumps FP rate on dead code.
2. **Cross-provider cache portability** — cache key currently includes model id, so Gemini cache doesn't help Groq. A canonicalised semantic key (prompt + finding fingerprint) would let providers warm each other's cache.
3. **Self-scan in CI** — eat our own dog food on every PR.
4. **Marketplace-packaged GitHub Action** — `uses: nb1b3k/secureflow-ai@v1`.

Open questions and v1 architectural decisions are tracked in `ARCHITECTURE.md §7–§8`.
