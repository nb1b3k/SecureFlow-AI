# Design Docs

Per-subsystem deep-dive specs. Each doc covers one subsystem's goals, interface, implementation notes, failure modes, file layout, acceptance criteria, and open questions.

These docs are written **before code**. They are updated as the code is built. They are the canonical source for component contracts; `ARCHITECTURE.md` in the project root is the high-level catalog that points here.

## Index

| Doc | Subsystem | Companion in ARCHITECTURE.md |
|---|---|---|
| `01_llm_stack.md` | Provider abstraction, Gemini client, Ollama/HF stubs, cache, budget, prompt registry, prompt-injection defense, secret masking. | §2.7 |
| `02_orchestrator.md` | LangGraph topology, state schema, node contracts, parallel fan-out, conditional edges, error classes, determinism. | §2.4, §3 |
| `03_patch_validation.md` | Patch generation + temp-worktree + scanner re-run + verification status taxonomy. | §2.5 (patch_agent) |
| `04_evaluation_harness.md` | Baseline vs full-pipeline measurement, fixture format, metrics, reproducibility, CI integration. | §2.11 |
| `05_schemas_and_finding_ids.md` | Full Pydantic models, validation discipline, stable finding-ID hashing scheme, code fingerprint normalization. | §2.3, §3, §5 |
| `06_sensitive_detection_and_reachability.md` | AST-signal-based sensitive-file detection + one-hop reachability heuristic. | §2.5 (context_agent, reachability_filter) |

## Doc template

When adding a new design doc:

```markdown
# Design NN — <Subsystem>

> Detailed spec for `secureflow.<module>.*`. Companion to `ARCHITECTURE.md §X`. Status: design | scaffolded | in-progress | complete.

## 1. Goal
## 2. Interface
## 3. Implementation notes
## 4. Failure modes
## 5. File layout
## 6. Acceptance criteria
## 7. Open questions
```

Bump `NN` to the next free integer. Add an Index entry above. Add a "Companion in ARCHITECTURE.md" line.
