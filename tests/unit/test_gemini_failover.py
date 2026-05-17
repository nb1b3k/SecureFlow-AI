"""Unit tests for the Gemini model-fallback path.

We stub `_client.models.generate_content` to make the first model raise
a daily-cap 429 and the fallback model succeed. The client should
transparently switch and return the second result.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from secureflow.schemas.llm_outputs import AIDiscoveryResponse

# Build a minimal "429 daily" exception body that _is_daily_exhausted matches.
_DAILY_429_BODY = (
    "429 RESOURCE_EXHAUSTED. {'error': {'code': 429, 'message': 'Quota exceeded "
    "for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, "
    "limit: 0, model: gemini-2.0-flash-lite'.', 'status': 'RESOURCE_EXHAUSTED', "
    "'details': [{'@type': 'type.googleapis.com/google.rpc.QuotaFailure', "
    "'violations': [{'quotaId': 'GenerateRequestsPerDayPerProjectPerModel-FreeTier'}]}]}}"
)


class _FakeGenaiModule:
    """Stand-in for the lazy-imported `google.genai` module.

    The Gemini client lazy-imports `from google import genai` inside its
    `__init__`. Tests would normally need the real package installed,
    which is fine for our venv — but we want to *control* generate_content
    behavior, so the test patches the client's `_client` attribute
    directly after construction.
    """


@pytest.fixture
def env_with_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")


def _build_response(text: str = '{"findings": []}'):
    resp = MagicMock()
    resp.text = text
    resp.parsed = None
    usage = MagicMock()
    usage.prompt_token_count = 10
    usage.candidates_token_count = 5
    resp.usage_metadata = usage
    return resp


def test_failover_on_daily_cap_switches_model(env_with_key) -> None:
    """First model returns 429-daily, second model succeeds → response uses second."""
    from secureflow.llm.gemini_client import GeminiClient

    client = GeminiClient(
        model="primary-model",
        fallback_models=["fallback-model"],
    )
    # Replace the real SDK client with one whose generate_content is
    # scripted: first call raises daily-cap, second call returns OK.
    call_sequence: list[str] = []

    def side_effect(model, contents, config):  # noqa: ARG001
        call_sequence.append(model)
        if model == "primary-model":
            raise Exception(_DAILY_429_BODY)
        return _build_response()

    client._client = MagicMock()
    client._client.models.generate_content.side_effect = side_effect

    result = client.complete(
        system="x",
        user="y",
        schema=AIDiscoveryResponse,
        prompt_version="t@v1",
        temperature=0.1,
        max_tokens=128,
    )
    assert result.model == "fallback-model"
    assert call_sequence == ["primary-model", "fallback-model"]
    # The client's "current model" has switched for subsequent calls.
    assert client.model == "fallback-model"


def test_failover_skips_when_no_fallback_list(env_with_key) -> None:
    """Primary daily-capped + empty fallback list → RateLimitedError."""
    from secureflow.llm.gemini_client import GeminiClient, RateLimitedError

    client = GeminiClient(model="primary-only", fallback_models=[])

    client._client = MagicMock()
    client._client.models.generate_content.side_effect = Exception(_DAILY_429_BODY)

    with pytest.raises(RateLimitedError):
        client.complete(
            system="x", user="y",
            schema=AIDiscoveryResponse,
            prompt_version="t@v1",
        )


def test_failover_chains_through_all_models(env_with_key) -> None:
    """Two consecutive daily-cap responses → fall through to third model."""
    from secureflow.llm.gemini_client import GeminiClient

    client = GeminiClient(
        model="m1",
        fallback_models=["m2", "m3"],
    )

    seen: list[str] = []

    def side_effect(model, contents, config):  # noqa: ARG001
        seen.append(model)
        if model in {"m1", "m2"}:
            raise Exception(_DAILY_429_BODY)
        return _build_response()

    client._client = MagicMock()
    client._client.models.generate_content.side_effect = side_effect

    result = client.complete(
        system="x", user="y",
        schema=AIDiscoveryResponse,
        prompt_version="t@v1",
    )
    assert seen == ["m1", "m2", "m3"]
    assert result.model == "m3"
    assert client.model == "m3"
