"""Unit tests for OllamaClient.

The client talks to a local Ollama daemon over plain HTTP via stdlib
`urllib.request`. We monkeypatch `urlopen` so these tests never touch
the network and can verify:
  - happy path: response parses into the requested Pydantic schema,
  - cache hit short-circuits the second call,
  - malformed first response triggers one corrective retry,
  - HTTP errors become LLMError,
  - daemon-unreachable becomes LLMError with a helpful message.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from secureflow.config import LimitsConfig
from secureflow.llm.base import LLMError, LLMValidationError
from secureflow.llm.budget import BudgetTracker
from secureflow.llm.cache import ContentAddressedCache
from secureflow.llm.ollama_client import OllamaClient
from secureflow.schemas.llm_outputs import AIDiscoveryResponse


def _ollama_body(content: str, *, prompt_tokens: int = 12, eval_tokens: int = 8) -> bytes:
    """Build a fake Ollama /api/chat non-streaming response body."""
    return json.dumps({
        "model": "qwen2.5-coder:3b",
        "message": {"role": "assistant", "content": content},
        "prompt_eval_count": prompt_tokens,
        "eval_count": eval_tokens,
        "done": True,
    }).encode("utf-8")


class _FakeResponse:
    """Minimal stand-in for the object returned by urlopen()."""

    def __init__(self, body: bytes) -> None:
        self._buf = io.BytesIO(body)

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):  # noqa: D401
        return self

    def __exit__(self, *_exc):  # noqa: D401
        return False


def test_happy_path_parses_into_schema(tmp_path) -> None:
    """A valid JSON body becomes a Pydantic-validated LLMCallResult."""
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = OllamaClient(model="qwen2.5-coder:3b", cache=cache)

    body = _ollama_body('{"findings": []}')

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen",
               return_value=_FakeResponse(body)) as mock_open:
        result = client.complete(
            system="s",
            user="u",
            schema=AIDiscoveryResponse,
            prompt_version="t@v1",
        )

    assert mock_open.call_count == 1
    assert result.parsed.findings == []
    assert result.model == "qwen2.5-coder:3b"
    assert result.tokens_in == 12
    assert result.tokens_out == 8
    assert result.cache_hit is False
    assert result.validation_retries == 0


def test_cache_hit_skips_http_on_second_call(tmp_path) -> None:
    """Second identical call returns cache_hit=True and never calls urlopen."""
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = OllamaClient(model="qwen2.5-coder:3b", cache=cache)

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen",
               return_value=_FakeResponse(_ollama_body('{"findings": []}'))) as mock_open:
        first = client.complete(
            system="same-system", user="same-user",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )
        second = client.complete(
            system="same-system", user="same-user",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )

    assert mock_open.call_count == 1
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert second.latency_ms == 0


def test_corrective_retry_on_invalid_json(tmp_path) -> None:
    """First response is unparseable; client retries once and succeeds."""
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = OllamaClient(model="qwen2.5-coder:3b", cache=cache)

    bodies = [
        _FakeResponse(_ollama_body("not-json-at-all")),
        _FakeResponse(_ollama_body('{"findings": []}')),
    ]

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen",
               side_effect=bodies) as mock_open:
        result = client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )

    assert mock_open.call_count == 2
    assert result.parsed.findings == []
    # The first attempt was a validation failure, so retries should reflect it.
    assert result.validation_retries == 1


def test_two_validation_failures_raise_llm_validation_error(tmp_path) -> None:
    """If both attempts return unparseable content, raise LLMValidationError."""
    cache = ContentAddressedCache(root=tmp_path / "cache")
    client = OllamaClient(model="qwen2.5-coder:3b", cache=cache)

    bodies = [
        _FakeResponse(_ollama_body("garbage-1")),
        _FakeResponse(_ollama_body("garbage-2")),
    ]

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen",
               side_effect=bodies), pytest.raises(LLMValidationError):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )


def test_http_error_becomes_llm_error(tmp_path) -> None:
    """A 500 from Ollama is surfaced as LLMError with the status code."""
    client = OllamaClient(model="qwen2.5-coder:3b")

    err = urllib.error.HTTPError(
        url="http://localhost:11434/api/chat",
        code=500,
        msg="server error",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(b"internal boom"),
    )

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen", side_effect=err):
        with pytest.raises(LLMError, match="500"):
            client.complete(
                system="s", user="u",
                schema=AIDiscoveryResponse, prompt_version="t@v1",
            )


def test_daemon_unreachable_message_mentions_ollama_serve(tmp_path) -> None:
    """Network failure → LLMError that tells the user how to start the daemon."""
    client = OllamaClient(model="qwen2.5-coder:3b")
    err = urllib.error.URLError("connection refused")

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen", side_effect=err):
        with pytest.raises(LLMError, match="ollama serve"):
            client.complete(
                system="s", user="u",
                schema=AIDiscoveryResponse, prompt_version="t@v1",
            )


def test_budget_records_tokens_after_successful_call(tmp_path) -> None:
    """A successful call should bump the BudgetTracker counters."""
    budget = BudgetTracker(limits=LimitsConfig())
    client = OllamaClient(model="qwen2.5-coder:3b", budget=budget)

    with patch("secureflow.llm.ollama_client.urllib.request.urlopen",
               return_value=_FakeResponse(_ollama_body('{"findings": []}', prompt_tokens=7, eval_tokens=3))):
        client.complete(
            system="s", user="u",
            schema=AIDiscoveryResponse, prompt_version="t@v1",
        )

    snap = budget.snapshot()
    assert snap["tokens_in"] == 7
    assert snap["tokens_out"] == 3
    assert snap["llm_calls"] == 1
