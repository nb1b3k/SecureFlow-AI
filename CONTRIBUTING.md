# Contributing

Thanks for your interest in contributing. This file describes how the codebase is organized, what is expected in a PR, and how to run things locally.

## Local setup

```bash
# 1. Venv + editable install + scanners
python -m venv .venv
source .venv/bin/activate        # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]" semgrep checkov

# 2. Install the scanner binaries (gitleaks, grype). See README "Installation".

# 3. Env file
cp .env.example .env             # then set at least one provider API key

# 4. Run the unit tests
pytest tests/unit -q
```

For local development without consuming cloud LLM quota, use the Ollama backend:

```bash
ollama pull qwen2.5-coder:3b
secureflow scan --repo . --config examples/configs/secureflow.ollama.yml
```

## Project layout

| Path | Contents |
|---|---|
| `secureflow/agents/` | LangGraph nodes (one file per agent). Each is a function `state -> state-delta`. |
| `secureflow/orchestrator/` | LangGraph wiring, state schema, conditional edges. |
| `secureflow/llm/` | Provider clients (DeepSeek, Gemini, Groq, OpenRouter, Ollama), cache, budget, prompt registry, JSON-repair fallback. |
| `secureflow/llm/prompts/<agent>/<version>.yaml` | Versioned prompt files. Bump the version when changing a prompt; the cache invalidates cleanly. |
| `secureflow/schemas/` | Pydantic models (state, finding, LLM outputs). |
| `secureflow/tools/` | Wrappers around external tools (semgrep, gitleaks, grype, checkov, git, GitHub API). |
| `secureflow/eval/` | Fixture-based evaluation harness. |
| `tests/unit/` | Unit tests; must pass before merge. |
| `tests/fixtures/scenario_<N>_<name>/` | Intentionally vulnerable code + `expected.yaml` labels for the eval. |
| `design/` | Per-subsystem design specs. |
| `examples/configs/` | Alternative `.secureflow.yml` configurations. |

## What goes in a PR

- One logical change per PR. Bug fixes and feature work do not share a commit.
- Tests for new behavior. If a code path the existing suite does not cover is added, add a test.
- Commit messages follow `type: subject` (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). The body should explain *why*, not *what* the diff already shows.
- Do not commit `report.*`, `eval_*`, `reports/eval_*.json` (unless it is the canonical CI artifact), `.secureflow_cache/`, or anything in `.env*`. These are gitignored.

## Running scans and evals locally

```bash
# Single scan against a fixture (no LLM, fast iteration)
secureflow scan --repo tests/fixtures/scenario_04_sqli_diff --no-llm

# Eval against the full corpus (no LLM)
secureflow eval run --no-llm

# Eval with the Ollama backend (local, free, slow)
secureflow eval run --config examples/configs/secureflow.ollama.yml --llm-concurrency 1
```

## Where to look first

- New to the project: read `README.md`, then `ARCHITECTURE.md` §2.
- Changing an agent: read the relevant `design/0X_*.md` for the contract.
- Changing the prompt for an agent: bump the prompt version, do not edit in place.
- Touching the orchestrator graph: update `design/02_orchestrator.md` and add a wiring test in `tests/unit/test_orchestrator_graph.py`.

## License

MIT. See [`LICENSE`](LICENSE).
