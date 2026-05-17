"""Unit tests for ChainLLMClient.

The chain takes a list of LLMClients and tries them in order. Transient
errors (rate-limit / auth) trigger failover; everything else propagates.
We mock LLMClient behaviour directly — no HTTP — by passing in stub
clients that return canned LLMCallResult or raise canned exceptions.
"""

from __future__ import annotations

import pytest

from secureflow.llm.base import LLMCallResult, LLMClient, LLMError, LLMValidationError
from secureflow.llm.chain_client import ChainLLMClient
from secureflow.schemas.llm_outputs import AIDiscoveryResponse


class _Stub(LLMClient):
    """LLMClient that returns canned results or raises canned errors."""

    def __init__(self, *, name: str, result=None, raises: Exception | None = None) -> None:
        self.name = name
        self.model = name + "-model"
        self._result = result
        self._raises = raises
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._result


def _ok() -> LLMCallResult:
    return LLMCallResult(
        parsed=AIDiscoveryResponse(findings=[]),
        prompt_version="t@v1",
        model="ok-model",
        tokens_in=10, tokens_out=5,
    )


def _kwargs():
    return dict(
        system="s", user="u",
        schema=AIDiscoveryResponse, prompt_version="t@v1",
    )


def test_chain_rejects_empty_clients_list() -> None:
    with pytest.raises(ValueError):
        ChainLLMClient(clients=[])


def test_primary_success_does_not_call_fallbacks() -> None:
    p = _Stub(name="primary", result=_ok())
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    chain.complete(**_kwargs())
    assert p.calls == 1
    assert f.calls == 0


def test_chain_falls_through_on_rate_limit() -> None:
    class _RateLimitedError(LLMError):
        pass
    p = _Stub(name="primary", raises=_RateLimitedError("rate_limited"))
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    chain.complete(**_kwargs())
    assert p.calls == 1
    assert f.calls == 1


def test_chain_falls_through_on_config_error() -> None:
    class _ConfigError(LLMError):
        pass
    p = _Stub(name="primary", raises=_ConfigError("api key missing"))
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    chain.complete(**_kwargs())
    assert p.calls == 1
    assert f.calls == 1


def test_chain_falls_through_on_validation_error() -> None:
    """Persistent schema-validation failure IS transient — that's a "this
    model can't follow our JSON schema" signal, and the next provider
    may handle it fine. Evidence: PR #7 pre-prod run where OpenRouter's
    `deepseek-v4-flash:free` returned Chinese-character salad for
    `ExploitabilityResult` while Groq's `llama-3.1-8b-instant` produces
    valid output on the same prompt.
    """
    p = _Stub(name="primary", raises=LLMValidationError(
        "openrouter did not produce a valid ExploitabilityResult after retries: "
        "7 validation errors for ExploitabilityResult"
    ))
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    chain.complete(**_kwargs())
    assert p.calls == 1
    assert f.calls == 1


def test_chain_re_raises_non_transient_network_error_on_first_client() -> None:
    """Network errors propagate — the next provider can't fix DNS or
    a stuck connection any better than the first. Bare `LLMError` with
    a network-flavored message stays non-transient.
    """
    p = _Stub(name="primary", raises=LLMError("could not reach <provider>: DNS failure"))
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    with pytest.raises(LLMError):
        chain.complete(**_kwargs())
    assert p.calls == 1
    assert f.calls == 0


def test_chain_raises_last_transient_when_all_fail() -> None:
    class _RateLimitedError(LLMError):
        pass
    p = _Stub(name="primary", raises=_RateLimitedError("p limited"))
    f = _Stub(name="fallback", raises=_RateLimitedError("f limited"))
    chain = ChainLLMClient(clients=[p, f])
    with pytest.raises(LLMError) as exc:
        chain.complete(**_kwargs())
    # The error from the LAST provider wins (caller sees the most recent attempt).
    assert "f limited" in str(exc.value)


def test_chain_skips_transient_in_middle_and_succeeds_later() -> None:
    class _RateLimitedError(LLMError):
        pass
    a = _Stub(name="a", raises=_RateLimitedError("a"))
    b = _Stub(name="b", raises=_RateLimitedError("b"))
    c = _Stub(name="c", result=_ok())
    chain = ChainLLMClient(clients=[a, b, c])
    chain.complete(**_kwargs())
    assert a.calls == 1
    assert b.calls == 1
    assert c.calls == 1


def test_chain_recognises_groq_rate_limited_by_class_name() -> None:
    """Real GroqRateLimitedError isn't imported here; chain detection is
    by class-name substring so it works across providers without coupling."""
    class GroqRateLimitedError(LLMError):
        pass
    p = _Stub(name="primary", raises=GroqRateLimitedError("groq 429"))
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    chain.complete(**_kwargs())
    assert f.calls == 1


def test_chain_falls_through_on_groq_413_tpm_overflow() -> None:
    """Groq returns HTTP 413 + body `rate_limit_exceeded` when the prompt
    is over its tokens-per-minute cap. Real example from PR #9 pre-prod:
    threat_model and ai_discovery both got `groq HTTP 413: {... "code":
    "rate_limit_exceeded" ...}`. The chain previously missed this because
    `rate_limited` (with -ed) wasn't a substring of `rate_limit_exceeded`.
    """
    p = _Stub(name="primary", raises=LLMError(
        'groq HTTP 413: {"error":{"message":"Request too large for model '
        '`llama-3.1-8b-instant` ... tokens per minute (TPM): Limit 6000, '
        'Requested 6880","type":"tokens","code":"rate_limit_exceeded"}}'
    ))
    f = _Stub(name="fallback", result=_ok())
    chain = ChainLLMClient(clients=[p, f])
    chain.complete(**_kwargs())
    assert p.calls == 1
    assert f.calls == 1
