"""Unit tests for the Phase 3 patch agent: generation + verification."""

from __future__ import annotations

from typing import TypeVar
from unittest.mock import patch

from pydantic import BaseModel

from secureflow.agents.patch_agent import patch_generation
from secureflow.llm.base import LLMCallResult, LLMClient
from secureflow.llm.budget import BudgetExceededError
from secureflow.llm.gemini_client import RateLimitedError
from secureflow.schemas.llm_outputs import PatchReplacement, PatchReview
from secureflow.tools.rescan import RescanResult

T = TypeVar("T", bound=BaseModel)


# ─────────────────────────────────────────────────────────────── helpers ──


def _finding(**kw) -> dict:
    base = {
        "id": "f" * 16,
        "source": "semgrep",
        "rule_id": "python.sqli",
        "title": "SQL injection",
        "description": "SQL injection via concatenation",
        "file_path": "app.py",
        "start_line": 5,
        "end_line": 5,
        "severity": "high",
        "confidence": 0.85,
        "evidence": "q = 'SELECT * FROM users WHERE id = ' + uid",
        "recommendation": "Use a parameterized query.",
        "cwe": ["CWE-89"],
        "owasp": [], "mitre_attack": [], "cve": [],
        "reachability": "unknown",
        "false_positive": False,
        "patch_status": "none",
    }
    base.update(kw)
    return base


def _state(findings: list[dict]) -> dict:
    return {
        "config": {
            "llm": {"provider": "gemini", "model": "gemini-2.0-flash-lite", "cache": False},
            "limits": {
                "max_patches_per_pr": 10,
                "max_patch_concurrency": 1,
                "max_llm_calls_per_pr": 50,
                "max_tokens_per_pr": 200_000,
            },
        },
        "pr_context": {"repo_path": "."},
        "exploitability_results": findings,
    }


class StubLLM(LLMClient):
    """Returns a configurable `PatchReplacement` per call.

    The agent now sends `schema=PatchReplacement` to the LLM (a tight
    3-field schema), so the stub speaks that contract. Tests that need a
    different replacement_code pass a custom `response`.
    """

    def __init__(
        self,
        response: PatchReplacement | None = None,
        *,
        raise_on_call: Exception | None = None,
    ) -> None:
        self.response = response
        self.raise_on_call = raise_on_call
        self.calls: list[dict] = []

    def complete(
        self, *, system, user, schema, prompt_version,
        temperature=0.1, max_tokens=2048,
    ):
        self.calls.append({"finding_id": _extract_id(user), "schema": schema.__name__})
        if self.raise_on_call is not None:
            raise self.raise_on_call
        # Return a schema-appropriate parsed object. The agent now makes
        # two distinct calls per finding (patch generation with
        # `PatchReplacement`, then a second-opinion review with
        # `PatchReview`). The stub speaks both contracts.
        fid = _extract_id(user)
        if schema is PatchReview:
            parsed = PatchReview(
                finding_id=fid,
                addresses_vulnerability=True,
                matches_code_context=True,
                concerns=[],
                confidence=0.9,
                verdict="approve",
            )
        else:
            parsed = (self.response or _default_replacement()).model_copy(
                update={"finding_id": fid}
            )
        return LLMCallResult[T](
            parsed=parsed,
            prompt_version=prompt_version,
            model="stub",
            tokens_in=100,
            tokens_out=80,
            cache_hit=False,
            latency_ms=1,
        )


def _extract_id(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("- id:"):
            return line.split(":", 1)[1].strip()
    return "missing"


def _default_replacement() -> PatchReplacement:
    return PatchReplacement(
        finding_id="x",
        replacement_code="    q = 'SELECT 1'  # safe replacement",
        explanation="Use parameterized SQL.",
    )


# The synth diff is deterministic enough to mock — these tests don't care
# about its exact bytes, only that downstream apply+rescan plumbing fires.
_FAKE_DIFF = (
    "--- a/app.py\n+++ b/app.py\n@@ -5,1 +5,1 @@\n-bad\n+good\n"
)


# ──────────────────────────────────────────────────────────────── tests ──


def test_ai_only_finding_is_not_applicable() -> None:
    f = _finding(source="ai_discovery", severity="high")
    out = patch_generation(_state([f]))
    assert len(out["final_findings"]) == 1
    assert out["final_findings"][0]["patch_status"] == "not_applicable"


def test_false_positive_skipped() -> None:
    f = _finding(false_positive=True)
    out = patch_generation(_state([f]))
    assert out["final_findings"][0]["patch_status"] == "none"
    assert "false positive" in out["final_findings"][0]["patch_verification_notes"].lower()


def test_info_severity_skipped() -> None:
    f = _finding(severity="info")
    out = patch_generation(_state([f]))
    assert out["final_findings"][0]["patch_status"] == "none"


def test_verified_when_rescan_clean() -> None:
    """LLM patch applies, scanner re-run reports no finding → verified."""
    stub = StubLLM()
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub), \
         patch("secureflow.agents.patch_agent._synthesise_diff_from_replacement", return_value=_FAKE_DIFF), \
         patch("secureflow.orchestrator.patch_loop.TempWorktree", _MockTempWorktree(apply_ok=True)), \
         patch("secureflow.agents.patch_agent.rerun_for", return_value=RescanResult(False)):
        out = patch_generation(_state([_finding()]))
    f = out["final_findings"][0]
    assert f["patch_status"] == "verified"
    assert f["patch_unified_diff"]


def test_unverified_when_scanner_still_flags() -> None:
    """Patch applies but the scanner re-run still reports the same finding."""
    stub = StubLLM()
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub), \
         patch("secureflow.agents.patch_agent._synthesise_diff_from_replacement", return_value=_FAKE_DIFF), \
         patch("secureflow.orchestrator.patch_loop.TempWorktree", _MockTempWorktree(apply_ok=True)), \
         patch("secureflow.agents.patch_agent.rerun_for", return_value=RescanResult(True)):
        out = patch_generation(_state([_finding()]))
    f = out["final_findings"][0]
    assert f["patch_status"] == "unverified"
    assert "still reports" in f["patch_verification_notes"]


def test_conflict_when_patch_doesnt_apply() -> None:
    stub = StubLLM()
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub), \
         patch("secureflow.agents.patch_agent._synthesise_diff_from_replacement", return_value=_FAKE_DIFF), \
         patch("secureflow.orchestrator.patch_loop.TempWorktree", _MockTempWorktree(apply_ok=False)):
        out = patch_generation(_state([_finding()]))
    f = out["final_findings"][0]
    assert f["patch_status"] == "conflict"


def test_synthesis_fails_when_file_missing() -> None:
    """If the file/line range can't be resolved, mark patch_status=none."""
    stub = StubLLM()
    # Note: no `_synthesise_diff_from_replacement` patch — the real function
    # runs and returns None because `app.py` doesn't exist at repo_path=".".
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub):
        out = patch_generation(_state([_finding()]))
    f = out["final_findings"][0]
    assert f["patch_status"] == "none"
    assert "couldn't be resolved" in f["patch_verification_notes"]


def test_rate_limit_trips_circuit_breaker() -> None:
    """First finding hits 429 → remaining findings skip LLM entirely."""
    stub = StubLLM(raise_on_call=RateLimitedError("daily quota"))
    fs = [_finding(id="a" * 16), _finding(id="b" * 16, title="other")]
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub):
        out = patch_generation(_state(fs))
    statuses = [f["patch_status"] for f in out["final_findings"]]
    notes = [f.get("patch_verification_notes") or "" for f in out["final_findings"]]
    # At least one is rate_limited, the other is rate_limited_skip.
    assert any("rate_limited" in (n or "") for n in notes)
    # Pipeline didn't crash.
    assert len(out["final_findings"]) == 2
    assert all(s == "none" for s in statuses)


def test_llm_unavailable_falls_back() -> None:
    """If we can't construct an LLM client, mark findings none with reason."""
    with patch(
        "secureflow.agents.patch_agent.build_patch_llm_client",
        side_effect=RuntimeError("no api key"),
    ):
        out = patch_generation(_state([_finding()]))
    f = out["final_findings"][0]
    assert f["patch_status"] == "none"
    assert "llm_unavailable" in (f["patch_verification_notes"] or "")


def test_max_patches_per_pr_caps_findings() -> None:
    """Findings past the cap get patch_status=none with reason."""
    findings = [_finding(id=f"{i:016x}", title=f"f{i}") for i in range(5)]
    stub = StubLLM()
    state = _state(findings)
    state["config"]["limits"]["max_patches_per_pr"] = 2
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub), \
         patch("secureflow.agents.patch_agent._synthesise_diff_from_replacement", return_value=_FAKE_DIFF), \
         patch("secureflow.orchestrator.patch_loop.TempWorktree", _MockTempWorktree(apply_ok=True)), \
         patch("secureflow.agents.patch_agent.rerun_for", return_value=RescanResult(False)):
        out = patch_generation(state)
    # Only 2 verified, the rest are 'none' with 'budget' note.
    verified = sum(1 for f in out["final_findings"] if f["patch_status"] == "verified")
    skipped_budget = sum(
        1 for f in out["final_findings"]
        if f["patch_status"] == "none" and "budget" in (f.get("patch_verification_notes") or "")
    )
    assert verified == 2
    assert skipped_budget == 3


def test_budget_exceeded_short_circuits() -> None:
    stub = StubLLM(raise_on_call=BudgetExceededError("tokens"))
    fs = [_finding(id="a"*16), _finding(id="b"*16, title="other")]
    with patch("secureflow.agents.patch_agent.build_patch_llm_client", return_value=stub):
        out = patch_generation(_state(fs))
    # Pipeline doesn't crash; both findings get a non-verified status.
    assert len(out["final_findings"]) == 2
    statuses = [f["patch_status"] for f in out["final_findings"]]
    assert all(s != "verified" for s in statuses)


# ─────────────────────────────────────────────────────────── mocking ──


def _MockTempWorktree(*, apply_ok: bool):
    """Factory: returns a callable that mimics TempWorktree(repo_path)."""

    class _Ctx:
        def __init__(self, *_args, **_kwargs) -> None:
            self.root = "/tmp/mock_worktree"

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

        def apply_patch(self, _diff: str) -> bool:
            return apply_ok

    return _Ctx
