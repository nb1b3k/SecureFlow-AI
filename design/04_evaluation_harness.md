# Design 04 — Evaluation Harness

> Detailed spec for `secureflow.eval.*`. Companion to `ARCHITECTURE.md §2.11`.
>
> **Why this matters.** The resume bullet (plan §23) and demo narrative (§14) make claims like "reduces false positives" and "finds scanner-missed flaws." Those claims need a number relative to a baseline. The eval harness produces that number reproducibly.

## 1. Goal

For a corpus of labeled vulnerable-PR fixtures, run **two pipelines** — `scanners_only` and `secureflow_full` — and compute:

- **Recall** (true positives / labeled positives): does the system find what we know is there?
- **Precision** (true positives / total positives reported): how clean are the results?
- **FP reduction**: `scanners_only.FP - secureflow_full.FP` (positive means SecureFlow's reasoning layer dropped FPs the scanners alone reported).
- **AI uplift**: `secureflow_full.TP - scanners_only.TP` (positive means AI Discovery found things scanners missed).
- **Latency per PR**: wall clock.
- **Token cost per PR**: tokens_in + tokens_out (per Gemini billing).
- **Patch success rate**: `verified / total_patches_attempted`.

The output is a Markdown table that drops directly into the README (plan §13).

## 2. Fixture format

Fixtures are committed to `tests/fixtures/` as **self-contained repo snapshots**, not as live git branches.

```
tests/fixtures/
├── scenario_01_sql_injection/
│   ├── repo/                       # before-state of the repo
│   │   ├── app.py
│   │   ├── requirements.txt
│   │   └── ...
│   ├── pr.diff                     # the change being reviewed
│   └── expected.yaml               # ground truth
├── scenario_02_hardcoded_secret/
│   └── ...
└── scenario_NN_false_positive/
    └── ...
```

### 2.1 expected.yaml schema

```yaml
scenario_id: scenario_01_sql_injection
description: SQL injection introduced via string concatenation in app.py
labels:
  - id: f1
    type: sql_injection
    file: app.py
    line_range: [12, 14]
    expected_severity: high
    expected_decision_contribution: FAIL
    expected_patch_strategy: parameterized_query
expected_decision: FAIL
expected_minimum_recall: 1.0          # must catch f1
expected_maximum_fp: 0                # ideally no false positives
notes: |
  Scanners alone should find this. AI exploitability should confirm high.
```

`labels` is the **ground truth set** of real vulnerabilities the fixture intentionally contains. A `scanner_FP` fixture has no labels but expects the system not to FAIL.

## 3. Two pipelines

### 3.1 `scanners_only`
Runs `secureflow scan` in a degraded mode that:
- Skips `ai_discovery` node entirely.
- Skips `exploitability` LLM step (findings pass through with their raw scanner severity).
- Still runs `threat_map` (deterministic table only — no LLM fallback).
- Still runs `decide` with the same policy engine.

This is **not** a fair comparison to raw Semgrep output — it includes our threat mapping and policy logic, which is what a "good DevSecOps wrapper without AI" would look like. That's the correct baseline.

### 3.2 `secureflow_full`
Runs `secureflow scan` with everything enabled, including AI discovery, exploitability reasoning, patch generation + validation.

### 3.3 Determinism
Both pipelines run with:
- Pinned scanner versions (recorded in `eval_versions.yaml`).
- Pinned LLM model + prompt versions.
- Cache enabled (so re-runs reproduce). For "freshness" runs that must hit the model, `--no-cache`.

## 4. Metrics computation

Per scenario, compute:
```python
@dataclass
class ScenarioResult:
    scenario_id: str
    pipeline: Literal["scanners_only", "secureflow_full"]
    tp: int          # findings matched to a label
    fp: int          # findings NOT matched to any label
    fn: int          # labels with no matching finding
    precision: float
    recall: float
    decision: str    # "PASS" | "WARN" | "FAIL"
    decision_correct: bool
    latency_ms: int
    tokens_in: int
    tokens_out: int
    patches_attempted: int
    patches_verified: int
```

### 4.1 Matching findings to labels

A reported finding matches a label if:
- `file_path` matches, AND
- their line ranges overlap, AND
- `type` matches (label's `type` maps to scanner rule IDs and AI Discovery title patterns via a thin alias table).

The alias table (`eval/label_aliases.yaml`) maps human-readable labels (`sql_injection`) to scanner rule IDs (`python.lang.security.audit.sqli.*` and similar) and AI title keywords (`sql injection`, `sqli`). This is where eval-truth-keeping happens; it's data-driven so adding a new fixture type doesn't require code changes.

## 5. Aggregate report

After running all scenarios:

```
| Scenario               | Pipeline       | TP | FP | FN | Recall | Decision | Latency | Tokens |
|------------------------|----------------|----|----|----|--------|----------|---------|--------|
| SQL injection          | scanners_only  | 1  | 0  | 0  | 1.00   | FAIL ✓   | 4.2s    | 0      |
| SQL injection          | secureflow_full| 1  | 0  | 0  | 1.00   | FAIL ✓   | 8.7s    | 3 421  |
| Business logic flaw    | scanners_only  | 0  | 0  | 1  | 0.00   | PASS ✗   | 3.1s    | 0      |
| Business logic flaw    | secureflow_full| 1  | 0  | 0  | 1.00   | WARN ✓   | 11.4s   | 5 102  |
| False-positive subproc | scanners_only  | 0  | 1  | 0  | -      | WARN ✗   | 3.4s    | 0      |
| False-positive subproc | secureflow_full| 0  | 0  | 0  | -      | PASS ✓   | 9.1s    | 2 880  |

Aggregate:
  Recall  : scanners_only 0.62  →  secureflow_full 0.94  (+0.32)
  FP rate : scanners_only 0.21  →  secureflow_full 0.04  (-81%)
  Decision correctness: 12/20  →  19/20
  Avg latency: 3.6s → 9.8s
  Avg tokens/PR: 0 → 3 412
```

This table goes into the README. It is **the** credibility artifact.

## 6. Reproducibility

`eval_versions.yaml` (committed):
```yaml
semgrep: "1.79.0"
gitleaks: "8.18.4"
grype: "0.78.0"
syft: "1.14.1"
gemini_model: "gemini-2.5-flash-lite"
prompt_versions:
  ai_discovery: "v1"
  exploitability: "v1"
  patch: "v1"
  threat_mapping: "v1"
secureflow_commit: "<filled by runner at run time>"
```

Each eval run writes a sibling `eval_run_<timestamp>.yaml` recording the actual versions used, so old reports remain interpretable.

## 7. CLI

```
secureflow eval run [--scenarios <glob>] [--pipelines scanners_only,full] \
                    [--no-cache] [--output eval_reports/<timestamp>.md]
secureflow eval list-scenarios
secureflow eval add-fixture <name>      # scaffolds a new fixture skeleton
```

## 8. CI hookup

Optional GitHub Action job `secureflow-eval.yml` that runs on:
- prompt YAML changes,
- scanner version bumps,
- merges to `main`.

It runs the eval and fails the CI if `aggregate_decision_correctness < threshold` (default 0.85) or `aggregate_recall < threshold` (default 0.80). This is the regression net for prompt and tool updates.

Caveat: this job is expensive in tokens; gate it behind a label like `run-eval` on PRs that don't touch prompts, or run only on `main`.

## 9. Fixture coverage targets

For v1 ship-ready (plan §22), we need **at least 20 fixtures** across categories:

| Category | Min fixtures |
|---|---|
| SQL injection | 2 (one easy, one with safe variant) |
| Command injection | 2 |
| SSRF | 2 |
| Hardcoded secrets | 3 (AWS, JWT, private key) |
| Vulnerable dependency | 3 (pip, npm, dockerfile-base-image) |
| Missing authorization | 2 |
| Business logic flaw | 2 |
| Insecure deserialization | 1 |
| Open redirect | 1 |
| Dangerous IAM policy | 1 |
| Scanner false positive (safe code that looks risky) | 3 |

Each fixture should be **minimal** — under ~100 LOC of pre-state and ~30 LOC of diff. Big fixtures slow the eval to a crawl and obscure what was being tested.

## 10. Anti-patterns to avoid

- **Don't eval against the training distribution.** The AI Discovery prompts must not be tuned by reading the eval fixtures' descriptions. Treat them as held-out.
- **Don't eval with cache hits and call it a "fresh run".** Reproducibility reports use cache; cost reports use `--no-cache`.
- **Don't aggregate without showing per-scenario breakdown.** Hiding bad scenarios in an average is the easiest way to lie with statistics.

## 11. File layout

```
secureflow/eval/
├── __init__.py
├── runner.py             # ScenarioRunner, aggregate
├── matcher.py            # finding ↔ label matching
├── label_aliases.yaml    # type → rule_id + AI keyword aliases
├── report.py             # Markdown table generation
└── cli.py                # `secureflow eval ...` subcommands

tests/fixtures/
├── scenario_01_sql_injection/
│   ├── repo/, pr.diff, expected.yaml
├── ...

eval_reports/             # gitignored; outputs of `secureflow eval run`
```

## 12. Acceptance criteria

- [ ] 20+ fixtures created and labeled per §9.
- [ ] `secureflow eval run` produces a Markdown table and a JSON sidecar for each scenario.
- [ ] Same input + same cache → same metrics (deterministic given prompt version).
- [ ] `eval_versions.yaml` is read and the actual run's `eval_run_*.yaml` is written.
- [ ] At least one fixture demonstrates `secureflow_full` outperforming `scanners_only` on recall.
- [ ] At least one fixture demonstrates `secureflow_full` outperforming `scanners_only` on FP reduction.
- [ ] The aggregate report is embedded in the README via a build step or copy.

## 13. Open questions

- **Q-EVAL-1:** Should we include a "competitor" pipeline (raw Semgrep, raw Snyk, etc.) for an external comparison? Recommendation: no for v1 — internal scanners-only vs full is the honest delta to report.
- **Q-EVAL-2:** Should patch validation be part of the eval (verified-rate metric)? Recommendation: yes — patches-verified-rate is the strongest single resume number we can produce.
- **Q-EVAL-3:** Where do labeled fixtures come from? Recommendation: hand-author for v1 (control quality), borrow from public corpora (DVWA, JuiceShop snippets) only if attributed clearly.
