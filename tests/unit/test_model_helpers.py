"""Regression tests for the cross-provider model-id leakage bug.

Live PR runs on nb1b3k/secureflow-ai-pr-test surfaced a bug where
`llm.model: deepseek/deepseek-v4-flash:free` (set for an OpenRouter
primary) leaked into Groq and Gemini fallback clients via the factory.
Groq returned HTTP 404 ("model_not_found") on every patch call.

These tests pin the contract:
  - openrouter_model() accepts only `vendor/model[:tag]`-shaped ids
  - groq_model() accepts only ids that are neither `gemini-*` nor `vendor/*`
  - gemini_model() accepts only `gemini-*`-shaped ids
  - Each falls through to its own default otherwise.
"""

from __future__ import annotations

from secureflow.config import (
    Config,
    LLMConfig,
    gemini_model,
    groq_model,
    openrouter_model,
)


def _cfg(model: str, provider: str = "gemini") -> Config:
    return Config(llm=LLMConfig(provider=provider, model=model))  # type: ignore[arg-type]


# ── gemini_model ──────────────────────────────────────────────────────


def test_gemini_keeps_gemini_shaped_ids() -> None:
    assert gemini_model(_cfg("gemini-2.5-flash-lite")) == "gemini-2.5-flash-lite"
    assert gemini_model(_cfg("gemini-2.0-flash")) == "gemini-2.0-flash"


def test_gemini_rejects_openrouter_id_and_uses_default() -> None:
    assert gemini_model(_cfg("deepseek/deepseek-v4-flash:free")) == "gemini-2.0-flash-lite"


def test_gemini_rejects_groq_id_and_uses_default() -> None:
    assert gemini_model(_cfg("llama-3.1-8b-instant")) == "gemini-2.0-flash-lite"


# ── groq_model ────────────────────────────────────────────────────────


def test_groq_keeps_groq_shaped_ids() -> None:
    assert groq_model(_cfg("llama-3.1-8b-instant")) == "llama-3.1-8b-instant"
    assert groq_model(_cfg("llama-3.3-70b-versatile")) == "llama-3.3-70b-versatile"
    assert groq_model(_cfg("gemma2-9b-it")) == "gemma2-9b-it"


def test_groq_rejects_gemini_id_and_uses_default() -> None:
    assert groq_model(_cfg("gemini-2.0-flash-lite")) == "llama-3.1-8b-instant"


def test_groq_rejects_openrouter_id_and_uses_default() -> None:
    # This is the exact id that broke patch generation on PR #2.
    assert groq_model(_cfg("deepseek/deepseek-v4-flash:free")) == "llama-3.1-8b-instant"


# ── openrouter_model ──────────────────────────────────────────────────


def test_openrouter_keeps_vendor_slash_ids() -> None:
    assert openrouter_model(_cfg("deepseek/deepseek-v4-flash:free")) == "deepseek/deepseek-v4-flash:free"
    assert openrouter_model(_cfg("meta-llama/llama-3.1-8b-instruct:free")) == "meta-llama/llama-3.1-8b-instruct:free"


def test_openrouter_rejects_plain_id_and_uses_default() -> None:
    # `gemini-2.0-flash-lite` and `llama-3.1-8b-instant` both lack the
    # vendor-slash separator that OpenRouter requires.
    assert openrouter_model(_cfg("gemini-2.0-flash-lite")) == "deepseek/deepseek-v4-flash:free"
    assert openrouter_model(_cfg("llama-3.1-8b-instant")) == "deepseek/deepseek-v4-flash:free"


# ── end-to-end: chain config inheritance ──────────────────────────────


def test_chain_config_uses_provider_specific_models() -> None:
    """The cause of the PR #2 patch-failure bug.

    Config has an OpenRouter primary + Groq + Gemini fallbacks. Each
    helper must produce a model id native to its OWN provider, not echo
    the primary's id.
    """
    cfg = Config(llm=LLMConfig(
        provider="openrouter",
        model="deepseek/deepseek-v4-flash:free",
        fallback_providers=["groq", "gemini"],
    ))
    assert openrouter_model(cfg) == "deepseek/deepseek-v4-flash:free"
    assert groq_model(cfg) == "llama-3.1-8b-instant"
    assert gemini_model(cfg) == "gemini-2.0-flash-lite"
