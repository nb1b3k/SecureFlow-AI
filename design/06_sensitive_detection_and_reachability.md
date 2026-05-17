# Design 06 — Sensitive-File Detection and Reachability

> Detailed spec for two thin agents/filters that gate expensive LLM work. Companion to `design/02_orchestrator.md §4.1` and `§4.8`.
>
> **Why one doc for both.** Both are *cheap heuristics over file content and structure* that produce signals consumed downstream by LLM-driven agents. They share infrastructure (tree-sitter / language registry) and design rhythm.

## 1. Sensitive-file detection

### 1.1 Why it matters

`ai_discovery` is the most expensive node (LLM tokens). Running it on every PR is wasteful — most PRs (docs, tests, internal utilities) are not security-sensitive. The plan's original mechanism (`sensitive_patterns` filename keywords) is brittle:

- **Misses:** `core.py` that defines auth routes is not flagged.
- **False-triggers:** `tests/test_auth.py` flagged but irrelevant.
- **Language-blind:** "permission" in a Java file means `import java.security.Permission`; in a billing config it might mean nothing security-relevant.

### 1.2 New approach — AST + import signals

A file is **sensitive** if at least one of these signals is true:

| Signal | Detection method |
|---|---|
| Defines a route/handler | AST match: decorators on functions matching `@app.route`, `@router.*`, `@app.get`/`post`/..., Express `app.get('/...', ...)`, Spring `@RequestMapping`, `@*Mapping`. |
| Imports an auth/session library | Import-name match against an allowlist: `flask.session`, `django.contrib.auth`, `jose`, `pyjwt`, `passlib`, `bcrypt`, `argon2`, `werkzeug.security`, `oauth*`, `passport`, `express-session`, `spring-security`. |
| Touches IAM / policy JSON | Filename: `*.iam.json`, `*policy*.json`, `*.tf` with `resource "aws_iam_*"`. |
| Defines cryptographic operations | Imports `cryptography`, `pycryptodome`, `nacl`, `crypto`. |
| Handles cookies / sessions directly | AST match: assignments to `response.cookies`, `request.cookies`, `request.session`, `req.cookies`. |
| Touches secrets manager APIs | Imports `boto3` with calls to `secretsmanager` / `ssm`, `google.cloud.secretmanager`, `vault`. |
| File path matches a path-based fallback | Path regex match: `.*/auth/.*`, `.*/payment/.*`, `.*/billing/.*`, `.*/admin/.*`, `.*/iam/.*`. **Lowest priority signal**; used only when no AST signal fires. |

### 1.3 Exclusion list

A file is **not** sensitive if **only** a path-based fallback fires AND the path also matches an exclusion:
- `tests/`, `test/`, `*_test.py`, `*.test.js`, `*.spec.ts`, `spec/`.
- `migrations/`, `alembic/`.
- `docs/`, `examples/`, `samples/`.
- `vendor/`, `third_party/`, `node_modules/`, `.venv/`, `__pycache__/`.

But: AST signals **override** the exclusion. `tests/conftest.py` with a real `@app.route` registration would still be flagged. The exclusion is for "looks like auth in the path but is just tests" cases.

### 1.4 Implementation

Two phases:
1. **Cheap regex pre-filter** runs on every file (path + first 200 lines text-scan for `@app.route` etc.). Cheap; eliminates ~80% of files.
2. **AST parse only on candidates.** Use tree-sitter via `tree-sitter-languages` (one Python wheel ships parsers for many languages, no per-language native build).

```python
class SensitiveDetector:
    def is_sensitive(self, file_path: str, content: str) -> tuple[bool, list[str]]:
        signals: list[str] = []
        if self._matches_route_decorator_regex(content):
            signals.append("route_decorator")
        if self._matches_auth_import_regex(content):
            signals.append("auth_import")
        if self._matches_iam_filename(file_path):
            signals.append("iam_policy_file")
        if self._matches_crypto_import_regex(content):
            signals.append("crypto_import")
        if signals:
            return True, signals
        # Fallback to path-based, with exclusion
        if self._matches_sensitive_path(file_path) and not self._matches_excluded_path(file_path):
            return True, ["sensitive_path"]
        return False, []
```

The signal list is recorded in `PRContext.sensitive_signals` so reviewers can see *why* AI Discovery ran (or didn't).

### 1.5 Performance

Target: < 500ms total across all changed files for a typical PR (~10-30 files). Per-file regex pre-filter is ~5-15ms; AST parse on 20% of files at ~30-100ms each. Stay under budget for the orchestrator's overall < 30s target.

### 1.6 Configuration

```yaml
ai_discovery:
  enabled: true
  run_on_all_prs: false                  # if true, skip detection entirely
  trigger_on_sensitive_files: true
  exclusion_paths:                       # overridable
    - tests/
    - migrations/
    - vendor/
  custom_signals:                        # user-defined extras
    auth_imports:
      - my_company.auth
    sensitive_paths:
      - billing/
```

## 2. Reachability heuristic

### 2.1 Why it matters

Note: the exploitability agent should know whether a finding is in code that *could* be reached at runtime. An SQLi in `tests/test_db.py` is structurally less dangerous than an SQLi in `routes/users.py`. Without this signal, the LLM treats both equally and may FAIL both.

### 2.2 What this is *not*

This is not a real static reachability analysis. We do not build a precise call graph. We do not track data flow. We compute a **hint** that lets the LLM and the policy engine apply common-sense weighting.

### 2.3 Algorithm

For each finding, produce one of `unreachable | likely_reachable | unknown`:

```
def classify(finding, repo) -> Reachability:
    # Step 1: path-based exclusion
    if file_under(finding.file_path, EXCLUDED_RUNTIME_DIRS):
        return "unreachable"

    # Step 2: enclosing symbol → look for one-hop callers
    if finding.symbol is None:
        return "unknown"

    callers = repo.find_callers(finding.symbol)
    if any(file_under(c.file, RUNTIME_DIRS) for c in callers):
        return "likely_reachable"
    if any(c.is_route_handler or c.is_main_entry for c in callers):
        return "likely_reachable"

    return "unknown"
```

Constants:
```python
EXCLUDED_RUNTIME_DIRS = {"tests", "test", "spec", "specs", "migrations",
                         "alembic", "examples", "samples", "docs",
                         "scripts/dev", "vendor", "third_party", "node_modules"}
RUNTIME_DIRS = {"app", "src", "routes", "handlers", "api", "services",
                "controllers", "lib"}
```

### 2.4 One-hop caller lookup

For Python: tree-sitter walk of all files in the repo, build a `symbol → calling_files` map. Cached per (commit_hash, repo_path).

For other languages: same approach using their tree-sitter grammars. Coverage in v1: Python, JavaScript, TypeScript, Go. Extend later.

Cost: one-time per scan (~1-2s on a medium repo). Cached for re-scans on same commit. The temp-worktree patch validation invalidates the cache for its own ephemeral worktree.

### 2.5 Pre-LLM severity adjustment

`reachability_filter` doesn't change severity — it sets the hint. But two downstream consumers use it:

1. **`exploitability` prompt** receives `reachability_hint` as part of the user message: *"This finding is in code with reachability hint `unreachable` — downgrade exploitability and confidence unless you can show concrete reachability."*
2. **`decide` policy engine** has rules like: "If `reachability == 'unreachable'` AND `severity != 'critical'`, downgrade to WARN even if scanner says high-confidence." This is documented in the report so reviewers can see why a finding was downgraded.

Importantly, `reachability == 'unreachable'` **never** overrides `gitleaks/critical` (a leaked secret in a test file is still a real leak). The override rule is scoped: it only weakens code-pattern findings, never secrets.

### 2.6 Output

`reachability_hints: dict[finding_id, Reachability]` on state. The normalizer reads this and copies into each finding's `reachability` field before exploitability runs.

## 3. Configuration

Both behaviors are configurable in `.secureflow.yml`:

```yaml
reachability:
  enabled: true
  excluded_runtime_dirs: [tests, migrations, examples, scripts, docs, vendor, third_party]
  runtime_dirs: [app, src, routes, handlers, api, services, controllers, lib]
  # Languages with tree-sitter caller lookup in v1
  enabled_languages: [python, javascript, typescript, go]

ai_discovery:
  enabled: true
  run_on_all_prs: false
  # See §1.6 for full sensitive-detection config
```

## 4. Failure modes

| Failure | Behavior |
|---|---|
| Tree-sitter parse failure | Skip AST signals for that file; fall back to regex/path heuristics. Logged but non-fatal. |
| One-hop caller lookup times out (large repo) | Set all findings in that repo to `unknown`. Don't block exploitability. |
| Sensitive detection fails on a file | Default to `sensitive=True` (fail-safe for security — better to over-trigger AI Discovery than to silently skip a real risk file). |

## 5. File layout

```
secureflow/agents/
├── context_agent.py               # uses SensitiveDetector
└── reachability_agent.py          # the reachability_filter node

secureflow/analysis/
├── __init__.py
├── ast_signals.py                 # SensitiveDetector
├── caller_index.py                # one-hop caller lookup via tree-sitter
└── path_rules.py                  # path classification constants and helpers
```

## 6. Acceptance criteria

### 6.1 Sensitive detection
- [ ] `tests/test_auth.py` (filename matches "auth" but is in tests) → not sensitive (returns `False`).
- [ ] `core.py` with `@app.route('/admin')` → sensitive (signal: `route_decorator`).
- [ ] `payment_service.py` with `import stripe` → sensitive (path + import).
- [ ] `migrations/0001_initial.py` → not sensitive even with auth-like content.
- [ ] `iam_policy.tf` with `resource "aws_iam_policy"` → sensitive.
- [ ] Custom signals from `.secureflow.yml > ai_discovery.custom_signals` are respected.
- [ ] Total detection time on a 50-file PR < 500ms.

### 6.2 Reachability
- [ ] Finding in `tests/test_users.py` → `unreachable`.
- [ ] Finding in `app/routes/login.py` → `likely_reachable`.
- [ ] Finding in a helper imported only by tests → `unreachable` (one-hop says callers are tests).
- [ ] Finding in a helper imported by `app/routes/...` → `likely_reachable`.
- [ ] Finding with no enclosing symbol detected → `unknown`.
- [ ] One-hop caller lookup completes < 2s on a 500-file repo.

## 7. Open questions

- **Q-SENS-1:** Should the sensitive detector ever consume content of the PR diff itself (e.g., "this PR introduces a route definition") in addition to file content? Recommendation: yes — diff is more current than file. Implementation note: the regex pre-filter should run on the post-diff file content, which is what `pr_context` already provides.
- **Q-REACH-1:** Two hops instead of one? Recommendation: no for v1 — diminishing returns and rapidly increasing analysis cost. Revisit if eval shows too many `unknown` classifications.
- **Q-REACH-2:** Should reachability classification be cached across PRs in the same repo (keyed on `git_tree_hash`)? Recommendation: yes — the caller graph rarely changes across consecutive PRs, and the cache key is cheap. Add in Phase 5 if perf is an issue.
- **Q-REACH-3:** Languages outside the v1 set (Java, Ruby, Rust, C#) → reachability falls back to `unknown`. Acceptable for v1? Recommendation: yes — document in README limitations.
