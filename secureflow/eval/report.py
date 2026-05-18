"""Markdown evaluation report — drops into the README's Evaluation section."""

from __future__ import annotations

from secureflow.eval.metrics import Aggregate, Delta, aggregate_for_mode, delta
from secureflow.eval.schema import PipelineRun, ScenarioResult


def render_markdown(results: list[ScenarioResult]) -> str:
    """Render an evaluation report from a list of ScenarioResult."""
    if not results:
        return "_No scenarios were evaluated._\n"

    lines: list[str] = ["# SecureFlow AI — Evaluation Report", ""]

    so = aggregate_for_mode(results, "scanners_only")
    sf = aggregate_for_mode(results, "secureflow_full")
    d = delta(so, sf)

    lines.extend(_render_summary(so, sf, d))
    lines.append("")
    lines.append("## Per-scenario breakdown")
    lines.append("")
    lines.append("| Scenario | Pipeline | Decision | TP | FP | FN | Recall | Precision | Latency | Tokens (in/out) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        if r.scanners_only is not None:
            lines.append(_row(r.scenario_id, r.scanners_only, r.expected.expected_decision))
        if r.secureflow_full is not None:
            lines.append(_row(r.scenario_id, r.secureflow_full, r.expected.expected_decision))

    # Surface scanner_errors per-scenario per-mode. The most common cause
    # of 0-delta numbers is a rate-limited LLM, and the reader deserves to
    # see that immediately rather than wonder why the LLM "did nothing".
    errors: list[str] = []
    for r in results:
        for mode_attr, mode_name in (
            ("scanners_only", "scanners_only"),
            ("secureflow_full", "secureflow_full"),
        ):
            run = getattr(r, mode_attr)
            if run is None or not run.scanner_errors:
                continue
            for component, msg in run.scanner_errors.items():
                if not _is_informative(msg):
                    continue
                short = msg.split("\n")[0]
                if len(short) > 200:
                    short = short[:200] + "…"
                errors.append(f"- **{r.scenario_id}** / `{mode_name}` / `{component}` — {short}")

    if errors:
        lines.append("")
        lines.append("## Scanner / agent errors")
        lines.append("")
        lines.extend(errors)

    notes: list[str] = []
    for r in results:
        if r.notes:
            notes.append(f"- **{r.scenario_id}** — " + "; ".join(r.notes))
    if notes:
        lines.append("")
        lines.append("## Notes")
        lines.extend(notes)

    lines.append("")
    return "\n".join(lines)


def _is_informative(msg: str) -> bool:
    """Filter out noise like 'no dependency manifests changed' which is just
    a documented skip, not an error worth surfacing in the report."""
    noisy = (
        "skipped: no dependency manifests changed",
        "no sensitive files changed",
        # scanners_only deliberately disables AI Discovery; this is the
        # expected state for that mode, not an error.
        "disabled in config",
        # Patch agent's per-finding "rate_limited_skip" is bookkeeping.
        "rate_limited_skip",
    )
    return not any(n in msg for n in noisy)


# ────────────────────────────────────────────────────── helpers ──


_DEC_BADGE = {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "FAIL": "❌ FAIL"}


def _row(scenario_id: str, run: PipelineRun, expected: str) -> str:
    dec = _DEC_BADGE.get(run.decision, run.decision)
    ok = " ✓" if run.decision_correct else f" ✗ (expected {expected})"
    return (
        f"| {scenario_id} | {run.mode} | {dec}{ok} | {run.true_positives} | "
        f"{run.false_positives} | {run.false_negatives} | "
        f"{run.recall:.2f} | {run.precision:.2f} | "
        f"{run.latency_ms / 1000:.1f}s | {run.tokens_in}/{run.tokens_out} |"
    )


def _render_summary(
    so: Aggregate | None,
    sf: Aggregate | None,
    d: Delta | None,
) -> list[str]:
    out: list[str] = ["## Aggregate", ""]
    headers = "| Metric | scanners_only | secureflow_full | Δ |"
    sep = "|---|---|---|---|"
    rows: list[str] = []

    def fmt(a: Aggregate | None, attr: str, kind: str) -> str:
        if a is None:
            return "—"
        v = getattr(a, attr)
        if kind == "pct":
            return f"{v * 100:.0f}%"
        if kind == "ms":
            return f"{v / 1000:.1f}s"
        return str(v)

    def diff(a, b, fmtfn) -> str:
        if a is None or b is None:
            return "—"
        if isinstance(a, float):
            return f"{(b - a) * 100:+.0f}%" if fmtfn == "pct" else f"{b - a:+.2f}"
        return f"{b - a:+d}"

    if so is not None and sf is not None:
        rows.append(f"| scenarios | {so.scenarios} | {sf.scenarios} | — |")
        rows.append(
            f"| recall | {so.recall:.2f} | {sf.recall:.2f} | "
            f"{(sf.recall - so.recall):+.2f} |"
        )
        rows.append(
            f"| precision | {so.precision:.2f} | {sf.precision:.2f} | "
            f"{(sf.precision - so.precision):+.2f} |"
        )
        rows.append(
            f"| decisions correct | {so.decisions_correct}/{so.scenarios} | "
            f"{sf.decisions_correct}/{sf.scenarios} | "
            f"{sf.decisions_correct - so.decisions_correct:+d} |"
        )
        rows.append(
            f"| total FP | {so.total_fp} | {sf.total_fp} | "
            f"{sf.total_fp - so.total_fp:+d} |"
        )
        rows.append(
            f"| total TP | {so.total_tp} | {sf.total_tp} | "
            f"{sf.total_tp - so.total_tp:+d} |"
        )
        # W22 — surface "secondary" findings (extra CVEs on a labeled
        # package, extra Checkov sub-checks on a labeled IaC resource).
        # They don't count as TP (1 label = 1 TP) but also don't count
        # as FP — the system correctly detected the labeled issue and
        # these are honest related findings the eval labels just didn't
        # enumerate. Surfacing the count keeps the metric transparent
        # without re-inflating the FP number.
        rows.append(
            f"| secondary findings (not FP) | {so.total_secondary} | "
            f"{sf.total_secondary} | "
            f"{sf.total_secondary - so.total_secondary:+d} |"
        )
        rows.append(
            f"| avg latency | {fmt(so, 'avg_latency_ms', 'ms')} | "
            f"{fmt(sf, 'avg_latency_ms', 'ms')} | "
            f"{(sf.avg_latency_ms - so.avg_latency_ms) / 1000:+.1f}s |"
        )
        rows.append(
            f"| tokens (in/out) | {so.total_tokens_in}/{so.total_tokens_out} | "
            f"{sf.total_tokens_in}/{sf.total_tokens_out} | "
            f"{sf.total_tokens_in - so.total_tokens_in:+d}/"
            f"{sf.total_tokens_out - so.total_tokens_out:+d} |"
        )
        rows.append(
            f"| patches verified | {so.patches_verified}/{so.patches_attempted} | "
            f"{sf.patches_verified}/{sf.patches_attempted} | "
            f"{sf.patches_verified - so.patches_verified:+d} |"
        )

    if rows:
        out.extend([headers, sep, *rows])
    elif so is not None or sf is not None:
        # Single-mode summary (e.g. `--no-llm` ran only scanners_only).
        single = so or sf
        assert single is not None
        out.extend([
            "| Metric | Value |",
            "|---|---|",
            f"| scenarios | {single.scenarios} |",
            f"| recall | {single.recall:.2f} |",
            f"| precision | {single.precision:.2f} |",
            f"| decisions correct | {single.decisions_correct}/{single.scenarios} |",
            f"| total TP/FP/FN | {single.total_tp}/{single.total_fp}/{single.total_fn} |",
            f"| avg latency | {single.avg_latency_ms / 1000:.1f}s |",
            f"| tokens (in/out) | {single.total_tokens_in}/{single.total_tokens_out} |",
            f"| patches verified | {single.patches_verified}/{single.patches_attempted} |",
        ])

    if d is not None:
        # `fp_reduced` is `scanners_only - full`, so positive means AI removed
        # FPs and negative means AI introduced new ones. Phrase the headline
        # accordingly so the narrative matches the sign.
        if d.fp_reduced > 0:
            fp_phrase = (
                f"FP reduced by **{d.fp_reduced} ({d.fp_reduction_pct:.0f}%)**"
            )
        elif d.fp_reduced < 0:
            added = -d.fp_reduced
            added_pct = -d.fp_reduction_pct
            pct_part = f" ({added_pct:.0f}% over baseline)" if added_pct else " (new FPs over a clean baseline)"
            fp_phrase = f"FP added by **{added}{pct_part}**"
        else:
            fp_phrase = "FP unchanged"
        out.append("")
        out.append(
            f"**Headline:** {fp_phrase}, "
            f"recall {('+' if d.recall_delta >= 0 else '')}{d.recall_delta:.2f}, "
            f"AI uplift {d.tp_uplift:+d} TP, "
            f"extra latency {d.extra_latency_ms / 1000:+.1f}s, "
            f"tokens {d.extra_tokens_in + d.extra_tokens_out:+,}."
        )

    return out
