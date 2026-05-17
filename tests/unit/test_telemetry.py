"""Unit tests for secureflow.reporting.telemetry.

The CLI is the only writer that calls these functions, so the tests
cover three things:
1. `build_telemetry` projects state into the documented shape.
2. `render_step_summary` produces non-empty Markdown for the documented
   keys (so a GH Actions reviewer sees something useful).
3. `maybe_write_step_summary` is a no-op when GITHUB_STEP_SUMMARY is
   absent, and appends (not overwrites) when present.
"""

from __future__ import annotations

import json

import pytest

from secureflow.reporting.telemetry import (
    build_telemetry,
    maybe_write_step_summary,
    render_step_summary,
    write_telemetry,
)


@pytest.fixture
def sample_state() -> dict:
    return {
        "decision": {
            "status": "FAIL",
            "risk_score": 92,
            "reasons": ["sqli@vulnerable.py:17", "missing_authz@routes.py:42"],
        },
        "final_findings": [
            {"source": "semgrep", "title": "sqli"},
            {"source": "semgrep", "title": "xss"},
            {"source": "ai_discovery", "title": "logic flaw"},
        ],
        "node_timings": {
            "collect_context": 15,
            "sast_scan": 7672,
            "ai_discovery": 4310,
            "decide": 2,
        },
        "budget_used": {"tokens_in": 1200, "tokens_out": 340, "llm_calls": 4},
        "scanner_errors": {"grype": "skipped: no manifests changed"},
        "prompt_versions": {"ai_discovery": "ai_discovery@v3", "patch": "patch@v2"},
    }


def test_build_telemetry_shape(sample_state: dict) -> None:
    out = build_telemetry(sample_state)

    assert out["decision"] == {"status": "FAIL", "risk_score": 92, "reasons_count": 2}
    assert out["findings"]["total"] == 3
    assert out["findings"]["by_source"] == {"semgrep": 2, "ai_discovery": 1}

    node_names = {n["name"] for n in out["nodes"]}
    assert node_names == {"collect_context", "sast_scan", "ai_discovery", "decide"}
    durations = {n["name"]: n["duration_ms"] for n in out["nodes"]}
    assert durations["sast_scan"] == 7672

    assert out["llm"] == {"tokens_in": 1200, "tokens_out": 340, "llm_calls": 4}
    assert out["scanners"] == {"grype": "skipped: no manifests changed"}
    assert out["prompts"]["ai_discovery"] == "ai_discovery@v3"
    # generated_at present and parseable
    assert "T" in out["generated_at"]


def test_build_telemetry_empty_state() -> None:
    """No findings, no decision yet, no LLM activity — shouldn't blow up."""
    out = build_telemetry({})
    assert out["decision"] is None
    assert out["findings"] == {"total": 0, "by_source": {}}
    assert out["nodes"] == []
    assert out["llm"] == {"tokens_in": 0, "tokens_out": 0, "llm_calls": 0}
    assert out["scanners"] == {}


def test_write_telemetry_round_trips(tmp_path, sample_state: dict) -> None:
    target = tmp_path / "sub" / "run_telemetry.json"
    written = write_telemetry(sample_state, target)
    assert written == target
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["decision"]["status"] == "FAIL"
    assert payload["findings"]["by_source"]["semgrep"] == 2


def test_render_step_summary_includes_key_signals(sample_state: dict) -> None:
    rendered = render_step_summary(build_telemetry(sample_state))
    # Decision visible
    assert "FAIL" in rendered
    assert "92" in rendered  # risk score
    # Tokens visible
    assert "1200" in rendered
    assert "340" in rendered
    # Worst-offender node leads the latency table
    lines = rendered.splitlines()
    sast_idx = next(i for i, line in enumerate(lines) if "sast_scan" in line)
    decide_idx = next(i for i, line in enumerate(lines) if "`decide`" in line)
    assert sast_idx < decide_idx, "nodes should be sorted by duration desc"
    # Scanner error surfaced
    assert "grype" in rendered


def test_maybe_write_step_summary_noop_without_env(
    monkeypatch: pytest.MonkeyPatch, sample_state: dict
) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert maybe_write_step_summary(build_telemetry(sample_state)) is None


def test_maybe_write_step_summary_appends_when_set(
    tmp_path, monkeypatch: pytest.MonkeyPatch, sample_state: dict
) -> None:
    summary_file = tmp_path / "summary.md"
    # Pre-seed so we can confirm append (not overwrite).
    summary_file.write_text("## Previous step\nkeep me\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    written = maybe_write_step_summary(build_telemetry(sample_state))
    assert written == summary_file
    final = summary_file.read_text(encoding="utf-8")
    assert "keep me" in final  # previous step preserved
    assert "FAIL" in final     # our summary appended
