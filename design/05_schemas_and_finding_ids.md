# Design 05 — Schemas and Finding IDs

> Detailed spec for `secureflow.schemas.*`. Companion to `ARCHITECTURE.md §2.3`.
>
> **Why this exists separately.** Schemas are the cross-cutting contract — every agent reads/writes them. Getting them right up front avoids painful migrations. The Finding ID scheme in particular needs to be designed deliberately because the bot's "update existing comment instead of spamming" behavior depends on it.

## 1. Goals

1. **Single canonical schema** for each object that crosses node boundaries. No drift, no duplicated definitions.
2. **Validatable** — Pydantic v2; every LLM-produced object passes through `model_validate_json`.
3. **Stable finding IDs** — survive whitespace edits, comment changes, and trivial reformats; only break on real semantic changes.
4. **Forward-compatible** — `model_config = ConfigDict(extra="ignore")` so adding fields doesn't break old caches.

## 2. The models

### 2.1 `Finding`

```python
from typing import Literal, Optional
from pydantic import BaseModel, Field, ConfigDict

Source = Literal["semgrep", "gitleaks", "grype", "osv", "bandit", "ai_discovery", "manual"]
Severity = Literal["info", "low", "medium", "high", "critical"]
PatchStatus = Literal["none", "suggested", "verified", "unverified", "conflict", "not_applicable"]
Reachability = Literal["unreachable", "likely_reachable", "unknown"]

class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Stable hash; see §3")
    source: Source
    rule_id: Optional[str] = Field(default=None, description="Scanner rule ID where applicable")
    title: str
    description: str

    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    symbol: Optional[str] = Field(default=None, description="Enclosing function/class name")

    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: Optional[str] = None

    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)

    reachability: Reachability = "unknown"
    exploitability: Optional[str] = None       # "none" | "low" | ... | "critical"
    attacker_scenario: Optional[str] = None
    impact: Optional[str] = None

    false_positive: bool = False
    false_positive_reason: Optional[str] = None

    recommendation: Optional[str] = None
    patch_unified_diff: Optional[str] = None
    patch_explanation: Optional[str] = None
    patch_status: PatchStatus = "none"
    patch_verification_notes: Optional[str] = None

    prompt_version: Optional[str] = Field(default=None, description="Prompt version that produced LLM fields, if any")
```

Notes:
- `id` is required, computed by the normalizer (see §3), never user-supplied.
- `confidence` for scanner findings is set from the scanner's reported confidence/severity per a deterministic table.
- `reachability` defaults to `unknown`; set by `reachability_filter` node.
- LLM-set fields (`exploitability`, `attacker_scenario`, `false_positive_reason`, patch fields) carry `prompt_version` so cached/older outputs are auditable.

### 2.2 `PRContext`

```python
class FunctionBoundary(BaseModel):
    file: str
    symbol: str             # function/class name
    start_line: int
    end_line: int
    language: str

class ChangedLineRange(BaseModel):
    file: str
    start: int
    end: int

class PRContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    repo_path: str
    repo_name: Optional[str] = None
    pr_number: Optional[int] = None
    base_branch: Optional[str] = None
    head_branch: Optional[str] = None

    changed_files: list[str]
    changed_line_ranges: list[ChangedLineRange]
    function_boundaries: list[FunctionBoundary]

    diff: str
    language_summary: dict[str, int]    # extension → file count

    sensitive_files_changed: bool
    sensitive_signals: list[str] = Field(default_factory=list)  # which AST/import signals triggered
```

### 2.3 `Decision`

```python
DecisionStatus = Literal["PASS", "WARN", "FAIL"]

class Decision(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: DecisionStatus
    risk_score: int = Field(ge=0, le=100)
    summary: str
    reasons: list[str]
    required_actions: list[str]
    finding_ids: list[str]              # contributing finding IDs

    skipped_components: list[str] = Field(default_factory=list)
    """e.g., ["ai_discovery: budget_exceeded", "gitleaks: subprocess_error"]"""
```

### 2.4 LLM-output schemas

These are **separate** from `Finding` because they're the *raw* shape the LLM returns. The normalizer/agent converts them into `Finding` instances.

```python
class AIDiscoveryItem(BaseModel):
    title: str
    description: str
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    exploit_scenario: str
    recommendation: str
    suggested_decision: Literal["PASS", "WARN", "FAIL"]

class AIDiscoveryResponse(BaseModel):
    findings: list[AIDiscoveryItem]

class ExploitabilityResult(BaseModel):
    finding_id: str
    exploitability: Literal["none", "low", "medium", "high", "critical"]
    adjusted_severity: Severity
    adjusted_confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    attacker_scenario: str
    false_positive: bool
    false_positive_reason: Optional[str] = None

class PatchSuggestion(BaseModel):
    finding_id: str
    patch_type: Literal["code", "dependency", "configuration", "manual"]
    unified_diff: Optional[str] = None
    explanation: str
    side_effects: str
    verification_steps: list[str]
```

Separation rationale: LLM may return invalid data → we validate the *response* schema, then merge into `Finding`. If we let the LLM produce a full `Finding` we'd have to make all its fields optional, weakening the rest of the codebase.

### 2.5 `SecurityReviewState`

Authoritative definition (replaces `ARCHITECTURE.md §3` placeholder):

```python
from typing import Annotated, TypedDict
from operator import add

def _merge_dict(a: dict, b: dict) -> dict: return {**a, **b}
def _sum_dict(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return out

class SecurityReviewState(TypedDict, total=False):
    # inputs
    config: dict
    pr_context: dict

    # parallel scanner outputs (need reducers)
    secret_findings: Annotated[list[dict], add]
    sast_findings: Annotated[list[dict], add]
    dependency_findings: Annotated[list[dict], add]
    ai_discovery_findings: Annotated[list[dict], add]

    # single-writer fields
    normalized_findings: list[dict]
    mapped_findings: list[dict]
    reachability_hints: dict[str, str]
    exploitability_results: list[dict]
    patch_results: list[dict]
    final_findings: list[dict]

    decision: dict
    markdown_report: str
    json_report_path: str
    sarif_report_path: str
    pr_comment_url: Optional[str]

    # bookkeeping (need reducers)
    budget_used: Annotated[dict[str, int], _sum_dict]
    scanner_errors: Annotated[dict[str, str], _merge_dict]
    prompt_versions: Annotated[dict[str, str], _merge_dict]
```

## 3. Finding ID scheme

### 3.1 Goals

- Same finding across re-pushes → same ID (so the bot edits its comment, doesn't spam).
- Different findings → different IDs.
- Trivial edits (whitespace, comments, variable renames not changing semantics) → same ID where possible.
- IDs are short enough to be human-readable in logs (16 hex chars = 64 bits of entropy).

### 3.2 Algorithm

```python
def compute_finding_id(
    source: str,
    rule_id: Optional[str],
    title: str,
    file_path: Optional[str],
    symbol: Optional[str],
    start_line: Optional[int],
    end_line: Optional[int],
    code_fingerprint: str,
) -> str:
    parts = [
        source,
        rule_id or _slug(title),
        _normalize_path(file_path or ""),
        _line_signature(symbol, start_line, end_line),
        code_fingerprint,
    ]
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]
```

### 3.3 Components

**`_slug(title)`** — when rule_id is missing (AI Discovery), use a title slug instead. `lowercase, strip non-alphanumeric, collapse whitespace to _, take first 6 words`. Stable across phrasing tweaks because LLM titles for the same issue are usually within a small Levenshtein neighborhood, but **not perfectly stable** — we accept some ID drift on AI findings as the cost of using title text. The reporting layer detects near-duplicates by (file, line ±5, source, similar title) and merges in the comment.

**`_normalize_path(p)`** — strip leading `./`, normalize separators to `/`, lowercase on case-insensitive filesystems? **No.** Keep case as-is, since case matters on Linux runners.

**`_line_signature(symbol, start, end)`** — `symbol or f"L{start}-{end}"`. If the scanner gave us an enclosing function/class name, use that (stable across reformat). Otherwise fall back to line range (less stable).

**`code_fingerprint`** — the offending lines, **normalized**:
1. Extract lines `[start_line, end_line]` from the file.
2. Remove single-line comments (`# ...` / `// ...`).
3. Collapse runs of whitespace to one space.
4. Strip string literal *content* but keep string-literal *markers* (so `"foo"` and `"bar"` collapse to `"_"` — same vulnerability, different data).
5. SHA-256 the result; take first 8 hex chars.

This means a hardcoded secret swap (`AKIA1234` → `AKIA5678` in the same code structure) produces the **same** fingerprint and same ID — so the bot updates its existing comment rather than spamming a new one. A *structural* change (parameterized query instead of string concat) produces a *different* fingerprint → ID changes → original finding's ID no longer present in re-scan → patch validation says `VERIFIED`.

### 3.4 Properties

| Scenario | ID stable? |
|---|---|
| Re-push without code changes | Yes |
| Reformat (whitespace, line breaks) | Yes (whitespace collapsed) |
| Renamed variable, same structure | Yes (data normalized) |
| Replaced secret value | Yes (literal content normalized) |
| Moved code from line 12 to line 30 within same function | Yes (symbol-based line signature) |
| Moved code to a different function | No (correct — semantically different location) |
| Patched (parameterized query) | No (correct — different code structure) |

### 3.5 Why not just hash the file + line?
- File hash changes on every edit, including unrelated edits in the same file.
- Line numbers shift on every push that adds/removes lines above.
- We'd post a new comment every time, defeating the "update-existing-comment" requirement (plan §8.11).

## 4. Migration policy

If a schema field is added: defaults provided, `extra="ignore"` means old cached JSON still loads. No migration needed.

If a schema field is removed or renamed: bump `prompt_version` for affected agents and clear `.secureflow_cache/`. The next run regenerates.

If the Finding ID algorithm changes: bump `FINDING_ID_VERSION` (TODO field on `Finding`) and force-update-rather-than-edit existing bot comment one time.

## 5. Validation discipline

Every place a `Finding` (or any model) crosses a trust boundary:
- LLM output → `Model.model_validate_json(text)`.
- Scanner JSON → custom adapter → `Model(**dict)`.
- Disk-cached JSON → `Model.model_validate_json(path.read_text())`.

Validation errors are caught, logged with `prompt_version`, and the affected item is dropped from the result (not the whole node).

## 6. File layout

```
secureflow/schemas/
├── __init__.py            # re-exports
├── finding.py             # Finding + enums
├── pr_context.py          # PRContext + FunctionBoundary + ChangedLineRange
├── decision.py            # Decision
├── llm_outputs.py         # AIDiscoveryResponse, ExploitabilityResult, PatchSuggestion
├── state.py               # SecurityReviewState + reducers
└── ids.py                 # compute_finding_id + code_fingerprint
```

## 7. Acceptance criteria

- [ ] Every model defined here is importable from `secureflow.schemas`.
- [ ] `Finding.model_validate(...)` rejects invalid severity, out-of-range confidence.
- [ ] `compute_finding_id` returns the same ID for the same content twice.
- [ ] `compute_finding_id` returns the same ID after a comment-only edit.
- [ ] `compute_finding_id` returns a different ID after a structural fix.
- [ ] LLM-output schemas are separate from `Finding` (no field overload).
- [ ] `model_config = ConfigDict(extra="ignore")` set on all models.

## 8. Open questions

- **Q-SCHEMA-1:** Should `code_fingerprint` use a language-aware tokenizer (tree-sitter) instead of whitespace-collapse for robustness? Recommendation: whitespace-collapse for v1 (no tree-sitter dependency), upgrade in v2 if false-new-ID rates become a problem.
- **Q-SCHEMA-2:** Should `confidence` be a continuous float or banded (`low`/`medium`/`high`)? Recommendation: continuous in storage; the policy engine bands it for decisions. Best of both.
- **Q-SCHEMA-3:** Should we record the *raw* scanner JSON for forensics, even though it's not a contract? Recommendation: yes — write to `<output>.raw/<scanner>.json` next to the JSON report. Not on `state` (would bloat) but on disk.
