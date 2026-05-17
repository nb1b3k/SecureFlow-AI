"""Unit tests for OpenRouterClient.

Same testing shape as test_groq_client.py — mock `urllib.request.urlopen`
so the tests never touch the network, patch `time.sleep` so the throttle
doesn't wait the real 3.5s gap.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from secureflow.llm.cache import ContentAddressedCache
from secureflow.llm.openrouter_client import (
    OpenRouterClient,
    OpenRouterConfigError,
    OpenRouterRateLimitedError,
)
from secureflow.schemas.llm_outputs import AIDiscoveryResponse


def _body(content: str, *, prompt_tokens: int = 12, completion_tokens: int = 8) -> bytes:
    return json.dumps({
        "id": "openrouter-test",
        "model": "deepseek/deepseek-v4-flash:free",
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


def _http_error(code: int, body: str, *, headers: dict | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://openrouter.ai/api/v1/chat/completions",
        code=code, msg="x",
        hdrs=headers or {},  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode("utf-8")),
    )


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("secureflow.llm.openrouter_client.time.sleep"):
        yield


@pytest.fixture(autouse=True)
def _reset_shared_throttle():
    import secureflow.llm.openrouter_client as orc
    orc._SHARED_LAST_CALL_AT = 0.0
    orc._SHARED_RATE_LIMITED_UNTIL = 0.0
    yield
    orc._SHARED_LAST_CALL_AT = 0.0
    orc._SHARED_RATE_LIMITED_UNTIL = 0.0


def test_init_rejects_missing_api_key() -> None:
    with pytest.raises(OpenRouterConfigError):
        OpenRouterClient(api_key="")


def test_happy_path(tmp_path) -> None:
    cache = ContentAddressedCache(root=tmp_path / "c")
    client = OpenRouterClient(api_key="sk-or-x", cache=cache)
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen",
               return_value=_FakeResponse(_body('{"findings": []}'))):
        r = client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    assert r.parsed.findings == []
    assert r.tokens_in == 12
    assert r.tokens_out == 8


def test_cache_hit_skips_http_on_second_call(tmp_path) -> None:
    cache = ContentAddressedCache(root=tmp_path / "c")
    client = OpenRouterClient(api_key="sk-or-x", cache=cache)
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen",
               return_value=_FakeResponse(_body('{"findings": []}'))) as mock_open:
        first = client.complete(system="x", user="y",
                                schema=AIDiscoveryResponse, prompt_version="t@v1")
        second = client.complete(system="x", user="y",
                                 schema=AIDiscoveryResponse, prompt_version="t@v1")
    assert mock_open.call_count == 1
    assert first.cache_hit is False
    assert second.cache_hit is True


def test_corrective_retry_on_invalid_json(tmp_path) -> None:
    cache = ContentAddressedCache(root=tmp_path / "c")
    client = OpenRouterClient(api_key="sk-or-x", cache=cache)
    bodies = [
        _FakeResponse(_body("not-json")),
        _FakeResponse(_body('{"findings": []}')),
    ]
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen",
               side_effect=bodies):
        r = client.complete(system="s", user="u",
                            schema=AIDiscoveryResponse, prompt_version="t@v1")
    assert r.validation_retries == 1


def test_401_raises_config_error() -> None:
    client = OpenRouterClient(api_key="sk-or-bad")
    err = _http_error(401, '{"error":{"message":"Invalid API Key"}}')
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen", side_effect=err), \
         pytest.raises(OpenRouterConfigError):
        client.complete(system="s", user="u",
                        schema=AIDiscoveryResponse, prompt_version="t@v1")


def test_429_raises_rate_limited_and_arms_cooldown() -> None:
    client = OpenRouterClient(api_key="sk-or-x")
    err = _http_error(
        429,
        '{"error":{"message":"Rate limit exceeded"}}',
        headers={"retry-after": "10"},
    )
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen", side_effect=err), \
         pytest.raises(OpenRouterRateLimitedError):
        client.complete(system="s", user="u",
                        schema=AIDiscoveryResponse, prompt_version="t@v1")
    # Class-level state armed for sibling instances.
    import secureflow.llm.openrouter_client as orc
    assert orc._SHARED_RATE_LIMITED_UNTIL > 0


def test_cooldown_fast_fails_instead_of_sleeping() -> None:
    """Once shared cooldown is armed, the next call must raise
    immediately so the chain can skip ahead to the next provider."""
    import secureflow.llm.openrouter_client as orc
    orc._SHARED_RATE_LIMITED_UNTIL = orc.time.monotonic() + 30.0
    client = OpenRouterClient(api_key="sk-or-x")
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen") as mock_open, \
         patch("secureflow.llm.openrouter_client.time.sleep") as mock_sleep, \
         pytest.raises(OpenRouterRateLimitedError, match="cooldown"):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
    assert mock_open.call_count == 0
    assert mock_sleep.call_count == 0


def test_inline_error_body_with_no_choices_handled() -> None:
    """OpenRouter sometimes returns 200 OK with an error in the body."""
    client = OpenRouterClient(api_key="sk-or-x")
    body = json.dumps({"error": {"message": "Rate limit reached"}}).encode("utf-8")
    with patch("secureflow.llm.openrouter_client.urllib.request.urlopen",
               return_value=_FakeResponse(body)), \
         pytest.raises(OpenRouterRateLimitedError):
        client.complete(system="s", user="u",
                        schema=AIDiscoveryResponse, prompt_version="t@v1")
