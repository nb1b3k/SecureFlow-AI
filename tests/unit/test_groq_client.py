"""Unit tests for GroqClient.

The client talks to Groq's OpenAI-compatible API over stdlib `urllib`.
We monkeypatch `urlopen` so these tests never touch the network and can
verify:

- happy path: an OpenAI-shaped response body parses into the requested
  schema, tokens + latency are recorded;
- cache hit short-circuits the second identical call;
- a malformed first response triggers one corrective retry;
- 401/403 raises GroqConfigError;
- 429 with a daily-quota body rotates `model` to the first fallback;
- 429 with a per-minute body sets `_rate_limited_until` and raises
  GroqRateLimitedError (caller decides what to do);
- missing api_key at construction raises GroqConfigError.

We also patch `time.sleep` so the per-call throttle (1.5s) doesn't make
the test suite slow.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from secureflow.llm.cache import ContentAddressedCache
from secureflow.llm.groq_client import (
    GroqClient,
    GroqConfigError,
    GroqRateLimitedError,
)
from secureflow.schemas.llm_outputs import AIDiscoveryResponse


def _groq_body(content: str, *, prompt_tokens: int = 12, completion_tokens: int = 8) -> bytes:
    """Build a fake Groq /chat/completions response body."""
    return json.dumps({
        "id": "chatcmpl-test",
        "model": "llama-3.1-8b-instant",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }).encode("utf-8")


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._buf = io.BytesIO(body)

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.fixture(autouse=True)
def _no_sleep():
    """Don't actually wait 2.5s between groq calls in unit tests."""
    with patch("secureflow.llm.groq_client.time.sleep"):
        yield


@pytest.fixture(autouse=True)
def _reset_shared_throttle():
    """Reset the module-level shared throttle state between tests so one
    test's cooldown doesn't leak into the next."""
    import secureflow.llm.groq_client as gc
    gc._SHARED_LAST_CALL_AT = 0.0
    gc._SHARED_RATE_LIMITED_UNTIL = 0.0
    yield
    gc._SHARED_LAST_CALL_AT = 0.0
    gc._SHARED_RATE_LIMITED_UNTIL = 0.0


def test_init_rejects_missing_api_key() -> None:
    with pytest.raises(GroqConfigError):
        GroqClient(api_key="")


def test_happy_path_parses_into_schema(tmp_path) -> None:
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = GroqClient(api_key="gsk_x", cache=cache)
    body = _groq_body('{"findings": []}')

    with patch("secureflow.llm.groq_client.urllib.request.urlopen",
               return_value=_FakeResponse(body)) as mock_open:
        result = client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )

    assert mock_open.call_count == 1
    assert result.parsed.findings == []
    assert result.tokens_in == 12
    assert result.tokens_out == 8
    assert result.cache_hit is False
    assert result.validation_retries == 0


def test_cache_hit_skips_http_on_second_call(tmp_path) -> None:
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = GroqClient(api_key="gsk_x", cache=cache)

    with patch("secureflow.llm.groq_client.urllib.request.urlopen",
               return_value=_FakeResponse(_groq_body('{"findings": []}'))) as mock_open:
        first = client.complete(
            system="same", user="same",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
        second = client.complete(
            system="same", user="same",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )

    assert mock_open.call_count == 1
    assert first.cache_hit is False
    assert second.cache_hit is True


def test_corrective_retry_on_invalid_json(tmp_path) -> None:
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = GroqClient(api_key="gsk_x", cache=cache)
    bodies = [
        _FakeResponse(_groq_body("not-json-at-all")),
        _FakeResponse(_groq_body('{"findings": []}')),
    ]
    with patch("secureflow.llm.groq_client.urllib.request.urlopen",
               side_effect=bodies) as mock_open:
        result = client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    assert mock_open.call_count == 2
    assert result.validation_retries == 1


def _http_error(code: int, body: str, *, headers: dict | None = None) -> urllib.error.HTTPError:
    msg = urllib.error.HTTPError(
        url="https://api.groq.com/openai/v1/chat/completions",
        code=code,
        msg="x",
        hdrs=headers or {},  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode("utf-8")),
    )
    return msg


def test_401_raises_groq_config_error() -> None:
    client = GroqClient(api_key="gsk_bad")
    err = _http_error(401, '{"error":{"message":"Invalid API Key"}}')
    with patch("secureflow.llm.groq_client.urllib.request.urlopen", side_effect=err), \
         pytest.raises(GroqConfigError):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )


def test_429_per_minute_raises_rate_limited_and_sets_cooldown() -> None:
    client = GroqClient(api_key="gsk_x")
    err = _http_error(
        429,
        '{"error":{"message":"Rate limit reached for requests"}}',
        headers={"retry-after": "5"},
    )
    with patch("secureflow.llm.groq_client.urllib.request.urlopen", side_effect=err), \
         pytest.raises(GroqRateLimitedError):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    assert client._rate_limited_until > 0  # cooldown armed
    # The per-minute body shouldn't rotate the model.
    assert client.model == "llama-3.1-8b-instant"


def test_429_per_day_rotates_to_fallback_model() -> None:
    client = GroqClient(
        api_key="gsk_x",
        model="llama-3.3-70b-versatile",
        fallback_models=["llama-3.1-8b-instant"],
    )
    err = _http_error(
        429,
        '{"error":{"message":"Rate limit reached for tokens per day (TPD)"}}',
        headers={"retry-after": "30"},
    )
    with patch("secureflow.llm.groq_client.urllib.request.urlopen", side_effect=err), \
         pytest.raises(GroqRateLimitedError):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    # Daily body triggers model rotation for the rest of the run.
    assert client.model == "llama-3.1-8b-instant"
    assert client.fallback_models == []  # consumed


def test_cooldown_fast_fails_instead_of_sleeping() -> None:
    """Once shared cooldown is armed (e.g. after a 429), the next call
    must raise immediately, not sleep through the cooldown — that's how
    the chain's failover stays fast."""
    import secureflow.llm.groq_client as gc
    # Arm a cooldown of 30s out.
    gc._SHARED_RATE_LIMITED_UNTIL = gc.time.monotonic() + 30.0
    client = GroqClient(api_key="gsk_x")
    with patch("secureflow.llm.groq_client.urllib.request.urlopen") as mock_open, \
         patch("secureflow.llm.groq_client.time.sleep") as mock_sleep, \
         pytest.raises(GroqRateLimitedError, match="cooldown"):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    # No HTTP attempt because we fast-failed.
    assert mock_open.call_count == 0
    # No sleep — the whole point of fast-fail.
    assert mock_sleep.call_count == 0


def test_throttle_enforces_min_gap_between_calls() -> None:
    """Successive calls call time.sleep if the gap is too small."""
    client = GroqClient(api_key="gsk_x")
    bodies = [
        _FakeResponse(_groq_body('{"findings": []}')),
        _FakeResponse(_groq_body('{"findings": []}')),
    ]
    with patch("secureflow.llm.groq_client.urllib.request.urlopen", side_effect=bodies), \
         patch("secureflow.llm.groq_client.time.sleep") as mock_sleep:
        client.complete(
            system="s1", user="u1",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
        client.complete(
            system="s2", user="u2",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    # At least one sleep call for the inter-call gap on the 2nd request.
    assert mock_sleep.call_count >= 1
