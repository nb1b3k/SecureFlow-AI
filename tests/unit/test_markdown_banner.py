"""Tests for the LLM-skip banner in render_markdown_report.

Without this banner, a reviewer seeing "no AI-discovered findings" can't tell
whether (a) the LLM ran and found nothing — good signal — or (b) the LLM was
silently truncated by quota/budget — should re-run before trusting the PASS.

The banner fires ONLY for actionable skips (budget, rate-limit, missing
credentials). Intentional `--no-llm` or "no sensitive files" skips don't
fire it — those aren't reviewer-actionable.
"""

from __future__ import annotations

from secureflow.reporting.markdown_report import _llm_skip_banner, render_markdown_report


def _state(scanner_errors: dict, status: str = "PASS") -> dict:
    return {
        "decision": {"status": status, "risk_score": 0, "summary": ""},
        "final_findings": [],
        "scanner_errors": scanner_errors,
        "pr_context": {},
    }


def test_banner_fires_on_budget_exceeded() -> None:
    out = _llm_skip_banner({"exploitability": "budget_exceeded: max_tokens_per_pr=20000 reached"})
    assert "AI analysis was partially skipped" in out
    assert "`exploitability`" in out


def test_banner_fires_on_rate_limit() -> None:
    out = _llm_skip_banner({"patch": "rate_limited: gemini daily free-tier quota exhausted"})
    assert "AI analysis was partially skipped" in out
    assert "`patch`" in out


def test_banner_fires_on_llm_unavailable() -> None:
    out = _llm_skip_banner({"exploitability": "llm_unavailable: ConfigError"})
    assert "AI analysis was partially skipped" in out


def test_banner_silent_when_llm_intentionally_disabled() -> None:
    out = _llm_skip_banner({"ai_discovery": "disabled in config"})
    assert out == ""


def test_banner_silent_when_no_sensitive_changes() -> None:
    out = _llm_skip_banner({"ai_discovery": "no sensitive files changed"})
    assert out == ""


def test_banner_ignores_scanner_failures() -> None:
    """gitleaks/semgrep/grype errors are scanner failures, not LLM truncation.
    They surface in the Notes section, not the top banner."""
    out = _llm_skip_banner({
        "gitleaks": "binary not found in PATH",
        "grype": "skipped: no dependency manifests changed",
    })
    assert out == ""


def test_banner_quotes_long_reason_truncated() -> None:
    long_reason = "rate_limited: " + ("x" * 500)
    out = _llm_skip_banner({"patch": long_reason})
    assert "…" in out  # ellipsis present
    assert "x" * 500 not in out  # original not embedded full


def test_banner_lists_multiple_agents() -> None:
    out = _llm_skip_banner({
        "exploitability": "rate_limited: 429",
        "patch": "budget_exceeded: capped at 20000 tokens",
    })
    assert "`exploitability`" in out
    assert "`patch`" in out


def test_full_report_includes_banner_above_decision() -> None:
    md = render_markdown_report(_state(
        {"patch": "rate_limited: gemini daily free-tier quota exhausted"}
    ))
    # Banner appears before the Decision line
    banner_idx = md.index("AI analysis was partially skipped")
    decision_idx = md.index("**Decision:**")
    assert banner_idx < decision_idx


def test_full_report_omits_banner_when_clean() -> None:
    md = render_markdown_report(_state({}))
    assert "AI analysis was partially skipped" not in md
