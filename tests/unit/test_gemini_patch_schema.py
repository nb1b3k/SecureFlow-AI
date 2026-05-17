"""Regression test: PatchReplacement flows through GeminiClient correctly.

Background: the patch_agent's contract with the LLM was reshaped to use the
tight `PatchReplacement` schema (3 required fields) instead of the wider
`PatchSuggestion`. We can't run a real Gemini call from CI (free-tier
quota; offline runs), but we CAN verify with a mock that:
  1. GeminiClient passes `response_schema=PatchReplacement` to the SDK
     (so Gemini's structured-output mode constrains the output correctly).
  2. The model's JSON response parses back into a `PatchReplacement`
     instance with the expected fields.

This is the per-provider regression test that complements
`test_patch_agent.py` (which uses a generic StubLLM).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from secureflow.schemas.llm_outputs import PatchReplacement


@pytest.fixture
def env_with_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")


def _fake_response(text: str = ""):
    """Stand-in for `models.generate_content(...)` return value."""
    resp = MagicMock()
    resp.text = text
    resp.parsed = None
    usage = MagicMock()
    usage.prompt_token_count = 50
    usage.candidates_token_count = 25
    resp.usage_metadata = usage
    return resp


def test_gemini_passes_patch_replacement_schema_to_sdk(env_with_key) -> None:
    """`client.complete(schema=PatchReplacement, ...)` must reach the SDK as
    `response_schema=PatchReplacement` in `GenerateContentConfig`."""
    from secureflow.llm.gemini_client import GeminiClient

    client = GeminiClient(model="gemini-2.0-flash-lite", fallback_models=[])

    captured: list = []

    def side_effect(model, contents, config):  # noqa: ARG001
        captured.append(config)
        return _fake_response(
            '{"finding_id":"abc123","replacement_code":"q = \\"SELECT 1\\"","explanation":"safer"}'
        )

    client._client = MagicMock()
    client._client.models.generate_content.side_effect = side_effect

    result = client.complete(
        system="s",
        user="FINDING:\n- id: abc123\n",
        schema=PatchReplacement,
        prompt_version="patch@v2",
        temperature=0.1,
        max_tokens=512,
    )

    # SDK was invoked with PatchReplacement as the response_schema.
    assert len(captured) == 1
    assert captured[0].response_schema is PatchReplacement
    assert captured[0].response_mime_type == "application/json"

    # Parsed payload is a PatchReplacement with the right shape.
    assert isinstance(result.parsed, PatchReplacement)
    assert result.parsed.finding_id == "abc123"
    assert result.parsed.replacement_code == 'q = "SELECT 1"'
    assert result.parsed.explanation == "safer"
    assert result.tokens_in == 50
    assert result.tokens_out == 25
    assert result.cache_hit is False


def test_gemini_corrective_retry_when_model_returns_empty_replacement(env_with_key) -> None:
    """If Gemini ignores min_length=1 and returns an empty replacement_code,
    the PatchReplacement validator rejects it and the client retries once
    with a corrective follow-up."""
    from secureflow.llm.gemini_client import GeminiClient

    client = GeminiClient(model="gemini-2.0-flash-lite", fallback_models=[])

    responses = [
        # First call: schema-violating (empty replacement_code).
        _fake_response('{"finding_id":"abc","replacement_code":"","explanation":"meh"}'),
        # Second call (corrective retry): valid.
        _fake_response(
            '{"finding_id":"abc","replacement_code":"q = ?","explanation":"safer"}'
        ),
    ]

    client._client = MagicMock()
    client._client.models.generate_content.side_effect = responses

    result = client.complete(
        system="s",
        user="u",
        schema=PatchReplacement,
        prompt_version="patch@v2",
    )

    assert result.parsed.replacement_code == "q = ?"
    assert result.validation_retries == 1
