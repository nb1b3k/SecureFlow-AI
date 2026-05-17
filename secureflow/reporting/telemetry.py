"""Run-telemetry artifact.

After the orchestrator completes, the CLI calls `build_telemetry(state)`
to produce a compact dict that describes what happened in the run:
per-node latency, LLM token usage, scanner error reasons, decision.
Written to `run_telemetry.json` and rendered as a tight table for
`$GITHUB_STEP_SUMMARY` so reviewers see latency/cost in the Actions run
UI without opening the SARIF file.

Intentionally cheap to compute and small enough to render inline. Cache
hit/miss counters are a known omission — the three agents that use the
cache each create their own `ContentAddressedCache` instance, so a
process-global hit/miss counter would need either a shared instance or a
classvar registry. Tracked as a follow-up.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_telemetry(state: dict[str, Any]) -> dict[str, Any]:
    """Project the orchestrator state into a stable, JSON-serializable shape.

    Returns a dict with these top-level keys:

    - `generated_at`: ISO-8601 timestamp of when the telemetry was built.
    - `decision`: `{status, risk_score, reasons_count}` or null if missing.
    - `findings`: counts (`total`, plus per-source breakdown).
    - `nodes`: list of `{name, duration_ms}` sorted by start order (best-effort
      via insertion order of `node_timings`).
    - `llm`: `{tokens_in, tokens_out, llm_calls}` from `budget_used`.
    - `scanners`: dict of scanner_name → error message (empty when all green).
    - `prompts`: dict of prompt_id → version used in this run.
    """
    decision = state.get("decision") or {}
    decision_view: dict[str, Any] | None = None
    if decision:
        decision_view = {
            "status": decision.get("status"),
            "risk_score": decision.get("risk_score"),
            "reasons_count": len(decision.get("reasons") or []),
        }

    final = state.get("final_findings") or state.get("normalized_findings") or []
    source_counts: dict[str, int] = {}
    for f in final:
        src = f.get("source") or "unknown"
        source_counts[src] = source_counts.get(src, 0) + 1

    node_timings = state.get("node_timings") or {}
    nodes = [{"name": k, "duration_ms": int(v)} for k, v in node_timings.items()]

    budget = state.get("budget_used") or {}
    llm = {
        "tokens_in": int(budget.get("tokens_in", 0)),
        "tokens_out": int(budget.get("tokens_out", 0)),
        "llm_calls": int(budget.get("llm_calls", 0)),
    }

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "decision": decision_view,
        "findings": {"total": len(final), "by_source": source_counts},
        "nodes": nodes,
        "llm": llm,
        "scanners": dict(state.get("scanner_errors") or {}),
        "prompts": dict(state.get("prompt_versions") or {}),
    }


def write_telemetry(state: dict[str, Any], path: str | Path) -> Path:
    """Build telemetry from `state` and write it as pretty JSON to `path`."""
    payload = build_telemetry(state)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return out


def render_step_summary(telemetry: dict[str, Any]) -> str:
    """Render telemetry as a compact Markdown table for GitHub step summary.

    Two tables: a one-row run summary (decision, totals, LLM cost) and a
    node-latency breakdown. Designed to be < 60 lines so it doesn't bury
    the Actions log.
    """
    d = telemetry.get("decision") or {}
    llm = telemetry.get("llm") or {}
    findings = telemetry.get("findings") or {}

    status = d.get("status") or "n/a"
    risk = d.get("risk_score") if d.get("risk_score") is not None else "n/a"

    lines: list[str] = []
    lines.append("## SecureFlow AI — run summary")
    lines.append("")
    lines.append("| Decision | Risk | Findings | Tokens (in/out) | LLM calls |")
    lines.append("|---|---|---|---|---|")
    lines.append(
        f"| {status} | {risk} | {findings.get('total', 0)} "
        f"| {llm.get('tokens_in', 0)} / {llm.get('tokens_out', 0)} "
        f"| {llm.get('llm_calls', 0)} |"
    )

    by_source = findings.get("by_source") or {}
    if by_source:
        lines.append("")
        lines.append("**Findings by source:** " + ", ".join(
            f"`{k}`={v}" for k, v in sorted(by_source.items())
        ))

    nodes = telemetry.get("nodes") or []
    if nodes:
        lines.append("")
        lines.append("### Node latency")
        lines.append("")
        lines.append("| Node | Duration (ms) |")
        lines.append("|---|---:|")
        for n in sorted(nodes, key=lambda x: -int(x.get("duration_ms", 0))):
            lines.append(f"| `{n['name']}` | {n['duration_ms']} |")

    scanners = telemetry.get("scanners") or {}
    if scanners:
        lines.append("")
        lines.append("### Scanner errors")
        lines.append("")
        for name, msg in sorted(scanners.items()):
            lines.append(f"- `{name}` — {msg}")

    return "\n".join(lines) + "\n"


def maybe_write_step_summary(telemetry: dict[str, Any]) -> Path | None:
    """If `$GITHUB_STEP_SUMMARY` is set, append the rendered summary to it.

    Returns the path written to, or None if we're not in GitHub Actions.
    GitHub appends step-summary contributions across steps, so we use append
    mode rather than overwrite.
    """
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return None
    body = render_step_summary(telemetry)
    path = Path(target)
    with path.open("a", encoding="utf-8") as f:
        f.write(body)
    return path
