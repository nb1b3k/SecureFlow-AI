"""Multi-provider LLM chain — try clients in order on rate-limit, auth,
or persistent schema-validation failures.

A chain wraps an ordered list of `LLMClient`s. On `.complete(...)`:

1. The first client is invoked.
2. If it raises a *transient and provider-specific* failure, the chain
   logs and falls through to the next. "Transient" includes:
     - rate-limit / quota exhaustion,
     - missing-key / auth / config errors,
     - **persistent schema-validation failure** — when a model can't
       produce valid JSON for our Pydantic schema after the inner
       corrective retry, that's a *model capability* limitation
       (this model can't follow the schema), not a logic bug in
       the prompt. Evidence: in PR #7's pre-prod run, OpenRouter's
       `deepseek-v4-flash:free` returned Chinese-character salad
       and `{}` for `ExploitabilityResult`, while Groq's
       `llama-3.1-8b-instant` produces valid output on the same
       prompt. Failover-on-validation lets us route around the
       weaker free model without giving up the LLM analysis
       entirely.
3. Any non-transient LLMError (network, e.g.) is re-raised.
4. The first success short-circuits.

Each wrapped client retains its own cache, so a hit on any link of the
chain still short-circuits live calls. Tokens are tracked against the
provider that actually served the call.

Used by the factory when `cfg.llm.fallback_providers` is non-empty:
the primary `provider` builds the head, each entry in
`fallback_providers` adds a tail link in order. A typical free-tier
config: `provider: openrouter`, `fallback_providers: [groq, gemini,
deepseek]` — most-generous quota first, paid tier last.
"""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from secureflow.llm.base import LLMCallResult, LLMClient, LLMError
from secureflow.utils.logging import get_logger

log = get_logger("llm.chain")
T = TypeVar("T", bound=BaseModel)


def _is_transient(exc: Exception) -> bool:
    """Should the chain try the next provider on this exception?

    True for:
      - rate-limit / quota (RateLimited* class names, `quota`, etc.).
      - auth / config (ConfigError class names, `api key`, `unauthorized`).
      - **validation** — `LLMValidationError` and the messages it emits
        ("did not produce a valid <schema> after retries"). One provider
        failing schema validation TWICE in a row means that *model* is
        bad at structured output for this schema; the next provider
        may not be.

    False for: network / timeout / unknown errors — those are bugs the
    next provider won't fix either (or will hit the same way).
    """
    name = type(exc).__name__.lower()
    if "ratelimited" in name or "rate_limited" in name:
        return True
    if "configerror" in name:
        return True
    if "validationerror" in name:
        # Both pydantic.ValidationError and our LLMValidationError land here.
        return True
    msg = (str(exc) or "").lower()
    if any(needle in msg for needle in (
        # Substring of `rate_limited`, `rate_limit_exceeded`, etc. —
        # don't require the trailing `-ed` because Groq's 413 body
        # says `rate_limit_exceeded` and we missed it before.
        "rate_limit", "rate limit", "resource_exhausted", "quota",
        "api key", "unauthorized", "unauthorised", "forbidden",
        # Groq returns HTTP 413 with "tokens per minute (TPM)" in the
        # body when the prompt is over the per-minute cap. That's a
        # transient situation — Gemini/DeepSeek may have more capacity.
        "tokens per minute", "tpm", "request too large",
        # Provider-specific 413/429/503 textual cues we've seen in
        # pre-prod logs that should route to the next link.
        "http 413", "http 429", "http 503",
    )):
        return True
    # Catches LLMValidationError's wrapped-message shape:
    # "<provider> did not produce a valid <SchemaName> after retries: ..."
    if "did not produce a valid" in msg or "validation error" in msg:
        return True
    return False


class ChainLLMClient(LLMClient):
    """Chains multiple LLMClients with provider-level failover."""

    name = "chain"

    def __init__(self, clients: list[LLMClient]) -> None:
        if not clients:
            raise ValueError("ChainLLMClient needs at least one client")
        self._clients = clients
        # Surface the head's model so logs/telemetry reflect the primary.
        self.model = getattr(clients[0], "model", "chain")

    def complete(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        prompt_version: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMCallResult[T]:
        last_exc: Exception | None = None
        for idx, client in enumerate(self._clients):
            try:
                result = client.complete(
                    system=system, user=user, schema=schema,
                    prompt_version=prompt_version,
                    temperature=temperature, max_tokens=max_tokens,
                )
                if idx > 0:
                    log.info(
                        "chain failover succeeded on link %d (%s after %d transient errors)",
                        idx, client.name, idx,
                    )
                return result
            except LLMError as e:
                if _is_transient(e) and idx < len(self._clients) - 1:
                    log.warning(
                        "chain link %d (%s) returned transient error; trying next: %s",
                        idx, client.name, str(e)[:200],
                    )
                    last_exc = e
                    continue
                # Non-transient or no more providers — re-raise.
                raise
        # All providers transient-failed.
        raise last_exc if last_exc else LLMError("chain exhausted with no result")
