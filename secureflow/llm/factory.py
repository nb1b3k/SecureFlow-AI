"""Build the right `LLMClient` for the current config.

When `cfg.llm.fallback_providers` is non-empty, the factory returns a
`ChainLLMClient` wrapping the primary provider followed by each fallback
provider in order. The chain transparently fails over on
rate-limit / auth errors so a free-tier user can chain
`openrouter -> groq -> gemini -> deepseek` and reach a successful
LLM-uplifted run without managing keys manually.

Provider-cost ordering matters: free tiers go first (most generous first),
paid tiers last. DeepSeek belongs at the tail because it's the only
prepaid-balance provider — every call costs real money, so it should
only fire when every free quota has been spent.
"""

from __future__ import annotations

from secureflow.config import (
    Config,
    deepseek_api_key,
    deepseek_model,
    gemini_model,
    groq_api_key,
    groq_model,
    openrouter_api_key,
    openrouter_model,
)
from secureflow.llm.base import LLMClient
from secureflow.llm.budget import BudgetTracker
from secureflow.llm.cache import ContentAddressedCache
from secureflow.llm.chain_client import ChainLLMClient

# Default Groq fallback chain — picked when the user hasn't set
# `llm.fallback_models` AND the primary is a Groq-shaped model id.
_DEFAULT_GROQ_FALLBACKS = [
    "llama-3.1-8b-instant",
    "gemma2-9b-it",
]


def _build_single(
    provider: str,
    cfg: Config,
    *,
    cache: ContentAddressedCache | None,
    budget: BudgetTracker | None,
) -> LLMClient:
    """Build one concrete provider client. Internal — see `build_llm_client`."""
    if provider == "gemini":
        from secureflow.llm.gemini_client import GeminiClient

        primary = gemini_model(cfg)
        fallbacks = [m for m in cfg.llm.fallback_models if m != primary]
        return GeminiClient(
            model=primary,
            fallback_models=fallbacks,
            cache=cache,
            budget=budget,
        )
    if provider == "ollama":
        from secureflow.llm.ollama_client import OllamaClient

        ollama_model = cfg.llm.model if ":" in cfg.llm.model else None
        return OllamaClient(
            model=ollama_model or "qwen2.5-coder:3b",
            cache=cache,
            budget=budget,
        )
    if provider == "groq":
        from secureflow.llm.groq_client import GroqClient

        primary = groq_model(cfg)
        user_fb = [m for m in cfg.llm.fallback_models if not m.startswith("gemini-")]
        fallbacks = [m for m in (user_fb or _DEFAULT_GROQ_FALLBACKS) if m != primary]
        return GroqClient(
            api_key=groq_api_key() or "",
            model=primary,
            fallback_models=fallbacks,
            cache=cache,
            budget=budget,
        )
    if provider == "openrouter":
        from secureflow.llm.openrouter_client import OpenRouterClient

        return OpenRouterClient(
            api_key=openrouter_api_key() or "",
            model=openrouter_model(cfg),
            cache=cache,
            budget=budget,
        )
    if provider == "deepseek":
        from secureflow.llm.deepseek_client import DeepSeekClient

        return DeepSeekClient(
            api_key=deepseek_api_key() or "",
            model=deepseek_model(cfg),
            cache=cache,
            budget=budget,
        )
    raise ValueError(f"Unknown llm.provider: {provider!r}")


def _build_chain(
    primary_name: str,
    fallback_names: list[str],
    cfg: Config,
    *,
    cache: ContentAddressedCache | None,
    budget: BudgetTracker | None,
) -> LLMClient:
    """Build a chain from a primary provider + an ordered list of fallbacks.

    Skips duplicates and providers that fail to construct (missing key
    is the common case). Returns the bare primary client when no
    fallbacks survive — chain-of-1 is wasteful overhead.
    """
    primary = _build_single(primary_name, cfg, cache=cache, budget=budget)
    if not fallback_names:
        return primary

    seen = {primary_name}
    clients: list[LLMClient] = [primary]
    for name in fallback_names:
        if name in seen:
            continue
        seen.add(name)
        try:
            clients.append(_build_single(name, cfg, cache=cache, budget=budget))
        except Exception as e:  # noqa: BLE001 - construction failure is non-fatal
            from secureflow.utils.logging import get_logger
            get_logger("llm.factory").warning(
                "fallback provider %r failed to construct, skipping: %s",
                name, e,
            )
    if len(clients) == 1:
        return clients[0]
    return ChainLLMClient(clients=clients)


def build_llm_client(
    cfg: Config,
    *,
    cache: ContentAddressedCache | None = None,
    budget: BudgetTracker | None = None,
) -> LLMClient:
    """Instantiate the configured provider, optionally wrapped in a
    cross-provider failover chain.

    Imports are local so a missing backend dependency only affects users
    who selected that backend.
    """
    return _build_chain(
        cfg.llm.provider,
        list(cfg.llm.fallback_providers),
        cfg,
        cache=cache,
        budget=budget,
    )


def build_patch_llm_client(
    cfg: Config,
    *,
    cache: ContentAddressedCache | None = None,
    budget: BudgetTracker | None = None,
) -> LLMClient:
    """Build the LLM chain for patch generation specifically.

    Patches require dramatically higher structured-output reliability
    than the other LLM stages: a bad exploitability downgrade just
    keeps the original scanner confidence; a garbage patch silently
    fills the bot comment with mojibake replacement code (e.g.
    OpenRouter free's `deepseek-v4-flash:free` returning Chinese /
    Greek / math salad for 1,092 tokens — actual pre-prod evidence).

    When `cfg.llm.patch_provider` is set we build a patch-specific
    chain from that provider + `patch_fallback_providers`. When unset,
    we fall back to the standard chain so existing configs aren't
    broken — but `.secureflow.yml` ships with the patch chain
    configured (`deepseek -> gemini -> groq`), so out-of-the-box runs
    skip the noisy free providers for the highest-stakes stage.
    """
    if cfg.llm.patch_provider is None:
        return build_llm_client(cfg, cache=cache, budget=budget)
    return _build_chain(
        cfg.llm.patch_provider,
        list(cfg.llm.patch_fallback_providers),
        cfg,
        cache=cache,
        budget=budget,
    )
