"""Groq LLM client — OpenAI-compatible HTTP API.

Groq runs open-weight models (Llama 3.x, Mixtral, Gemma) on custom LPU
hardware that's typically 5–10× faster end-to-end than Gemini at similar
quality. Their free tier gives roughly 30 RPM and ~6,000 RPD on the
smaller models, which is more headroom than Gemini's free tier for a
SecureFlow run.

Endpoint:  POST https://api.groq.com/openai/v1/chat/completions
Auth:      Authorization: Bearer ${GROQ_API_KEY}

The cache + budget plumbing mirrors GeminiClient. The 429 handling is
simpler than Gemini's: Groq returns a `retry-after` header (seconds) on
RPM exhaustion and a clean `error.message` on daily exhaustion, so we
parse those and either back off or rotate to `fallback_models`.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from secureflow.llm.base import (
    LLMCallResult,
    LLMClient,
    LLMError,
    LLMValidationError,
)
from secureflow.llm.budget import BudgetTracker
from secureflow.llm.cache import ContentAddressedCache
from secureflow.utils.logging import get_logger
from secureflow.utils.secret_masker import mask

log = get_logger("llm.groq")
T = TypeVar("T", bound=BaseModel)

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
REQUEST_TIMEOUT_SECONDS = 60

# Bound the per-minute call rate from the *client* side too, so a burst
# of parallel agent calls doesn't trip Groq's 30 RPM cap on the free tier.
# 2.5s between calls = 24 RPM, comfortably under the 30 cap with margin
# for the per-call latency that Groq's response time consumes. Burstier
# callers can raise this via config; we err safe.
_MIN_GAP_SECONDS = 2.5

# How long to honour a 429 cooldown before retrying. If the response
# included a `retry-after`, we use that instead.
_DEFAULT_BACKOFF_SECONDS = 8.0

# Class-level shared throttle state. Each agent (ai_discovery,
# exploitability, patch) constructs its own GroqClient via the factory.
# Without sharing, two concurrent GroqClients each enforce 2.5s gaps
# independently — net rate becomes 2× faster and bursts trip the 30 RPM
# cap. The classvars below serialise the throttle across every instance
# in the same process.
import threading as _threading  # noqa: E402

_SHARED_THROTTLE_LOCK = _threading.Lock()
_SHARED_LAST_CALL_AT: float = 0.0
_SHARED_RATE_LIMITED_UNTIL: float = 0.0


class GroqRateLimitedError(LLMError):
    """Groq returned 429. Surfaced separately so callers can label it."""


class GroqConfigError(LLMError):
    """Raised at init when GROQ_API_KEY is missing."""


class GroqClient(LLMClient):
    """LLMClient backed by Groq's OpenAI-compatible API."""

    name = "groq"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "llama-3.1-8b-instant",
        fallback_models: list[str] | None = None,
        cache: ContentAddressedCache | None = None,
        budget: BudgetTracker | None = None,
    ) -> None:
        if not api_key:
            raise GroqConfigError(
                "GROQ_API_KEY is not set. Get one free at "
                "https://console.groq.com/keys and put it in .env."
            )
        self._api_key = api_key
        self.model = model
        self.fallback_models: list[str] = list(fallback_models or [])
        self._cache = cache
        self._budget = budget
        self._last_call_at: float = 0.0
        self._rate_limited_until: float = 0.0
        log.info("groq client ready", extra={"model": self.model})

    # ------------------------------------------------------------------ public

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
        system_masked = mask(system)
        user_masked = mask(user)

        if self._cache is not None:
            cached = self._cache.get(
                prompt_version=prompt_version,
                model=self.model,
                temperature=temperature,
                system=system_masked,
                user=user_masked,
            )
            if cached is not None:
                try:
                    parsed = schema.model_validate(cached["parsed"])
                    return LLMCallResult[T](
                        parsed=parsed,
                        prompt_version=prompt_version,
                        model=self.model,
                        tokens_in=cached.get("tokens_in", 0),
                        tokens_out=cached.get("tokens_out", 0),
                        cache_hit=True,
                        latency_ms=0,
                    )
                except (KeyError, ValidationError):
                    pass  # fall through to live call

        if self._budget is not None:
            self._budget.reserve(estimated_tokens=max_tokens)

        last_error: Exception | None = None
        validation_retries = 0
        # One retry on schema validation failure (corrective follow-up).
        for attempt in range(2):
            try:
                content, tokens_in, tokens_out, latency_ms, served_by = self._call_groq(
                    system=system_masked,
                    user=user_masked if attempt == 0 else self._corrective(user_masked, last_error),
                    schema=schema,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except GroqRateLimitedError:
                raise  # caller decides whether to keep going
            except LLMError:
                raise

            if self._budget is not None:
                self._budget.record(tokens_in=tokens_in, tokens_out=tokens_out)

            try:
                parsed = self._validate(content, schema)
            except (ValidationError, json.JSONDecodeError) as ve:
                last_error = ve
                validation_retries += 1
                log.warning(
                    "groq response failed schema validation (attempt %d): %s",
                    attempt + 1,
                    str(ve)[:200],
                )
                continue

            if self._cache is not None:
                self._cache.put(
                    prompt_version=prompt_version,
                    model=self.model,
                    temperature=temperature,
                    system=system_masked,
                    user=user_masked,
                    value={
                        "parsed": parsed.model_dump(),
                        "tokens_in": tokens_in,
                        "tokens_out": tokens_out,
                    },
                )

            return LLMCallResult[T](
                parsed=parsed,
                prompt_version=prompt_version,
                model=served_by or self.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cache_hit=False,
                latency_ms=latency_ms,
                validation_retries=validation_retries,
            )

        raise LLMValidationError(
            f"groq did not produce a valid {schema.__name__} after retries: {last_error}"
        )

    # ----------------------------------------------------------------- private

    def _throttle(self) -> None:
        """Enforce the inter-call gap, but fast-fail when in cooldown.

        Two distinct delays here:
        - **Per-call gap** (`_MIN_GAP_SECONDS`): friendly throttle that
          serialises calls below the 30 RPM cap. We sleep through it.
        - **Cooldown after 429**: we previously *slept* until the
          retry-after window cleared. That stalls the chain — when this
          client is a non-primary link, the caller wants to skip ahead
          to the next provider, not block 20s for this one. So we now
          **raise** immediately if the cooldown is active. The chain's
          transient-error handler routes to the next link.

        Standalone callers (no chain) can re-call `complete()` after the
        cooldown elapses; the per-call gap still keeps them well-behaved.
        """
        global _SHARED_LAST_CALL_AT, _SHARED_RATE_LIMITED_UNTIL
        with _SHARED_THROTTLE_LOCK:
            now = time.monotonic()
            if now < _SHARED_RATE_LIMITED_UNTIL:
                wait_left = _SHARED_RATE_LIMITED_UNTIL - now
                # Mirror onto the instance attr so log/tests reflect state.
                self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL
                raise GroqRateLimitedError(
                    f"rate_limited: groq in cooldown for another {wait_left:.1f}s "
                    "(set per-client to dodge unbroken backoff stalls)"
                )
            gap = now - _SHARED_LAST_CALL_AT
            if gap < _MIN_GAP_SECONDS:
                time.sleep(_MIN_GAP_SECONDS - gap)
            _SHARED_LAST_CALL_AT = time.monotonic()
            self._last_call_at = _SHARED_LAST_CALL_AT
            self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL

    def _call_groq(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        temperature: float,
        max_tokens: int,
    ) -> tuple[str, int, int, int, str | None]:
        """Invoke Groq once. Returns (content, tokens_in, tokens_out, latency_ms, served_model)."""
        # Add the JSON schema to the system message so the model knows the
        # required shape. Combined with `response_format={"type": "json_object"}`
        # this is reliable across Groq-hosted models. Per Groq docs we MUST
        # mention "json" somewhere in the prompt to activate json_object mode.
        schema_str = json.dumps(schema.model_json_schema(), indent=2)
        system_with_schema = (
            system + "\n\n"
            "Return ONLY a JSON object that matches this schema. "
            "Do not include any prose, markdown fences, or explanation outside the JSON.\n\n"
            f"Schema:\n{schema_str}"
        )

        body: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_with_schema},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }

        self._throttle()

        req = urllib.request.Request(
            GROQ_ENDPOINT,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
        )
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "secureflow-ai/0.1")

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - best effort
                pass
            if e.code == 429:
                # Honour `retry-after` if present, else use default backoff.
                retry_after = float(
                    e.headers.get("retry-after") or _DEFAULT_BACKOFF_SECONDS
                )
                # Publish to shared state so other concurrent GroqClient
                # instances also back off — not just this one.
                global _SHARED_RATE_LIMITED_UNTIL
                with _SHARED_THROTTLE_LOCK:
                    _SHARED_RATE_LIMITED_UNTIL = max(
                        _SHARED_RATE_LIMITED_UNTIL,
                        time.monotonic() + retry_after,
                    )
                    self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL
                self._maybe_rotate_model(err_body)
                raise GroqRateLimitedError(
                    f"rate_limited: groq 429 (retry-after={retry_after:.1f}s): {err_body[:300]}"
                ) from e
            if e.code in (401, 403):
                raise GroqConfigError(
                    f"groq auth failed ({e.code}). Check GROQ_API_KEY."
                ) from e
            raise LLMError(f"groq HTTP {e.code}: {err_body[:400]}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMError(f"could not reach Groq: {e}") from e

        elapsed_ms = int((time.monotonic() - start) * 1000)
        choices = payload.get("choices") or []
        if not choices:
            raise LLMError(f"groq returned no choices: {str(payload)[:400]}")
        content = ((choices[0].get("message") or {}).get("content")) or ""
        usage = payload.get("usage") or {}
        tokens_in = int(usage.get("prompt_tokens") or 0)
        tokens_out = int(usage.get("completion_tokens") or 0)
        served_by = payload.get("model")
        return content, tokens_in, tokens_out, elapsed_ms, served_by

    def _maybe_rotate_model(self, err_body: str) -> None:
        """If a fallback model is available and the 429 looks like a per-day
        cap (not a per-minute burst), switch to it for the rest of the run.
        """
        low = err_body.lower()
        looks_daily = "per day" in low or "daily" in low or "tpd" in low
        if looks_daily and self.fallback_models:
            new_model = self.fallback_models.pop(0)
            log.warning(
                "groq daily quota exhausted on %s; rotating to %s for the rest of this run",
                self.model, new_model,
            )
            self.model = new_model
            # Clear the cooldown — the new model has its own quota bucket.
            self._rate_limited_until = 0.0

    @staticmethod
    def _validate(content: str, schema: type[T]) -> T:
        """Parse the model's text response and validate against the schema.

        Uses the shared `parse_with_repair` fallback so almost-valid JSON
        recovers without burning a corrective-retry LLM call.
        """
        from secureflow.llm._json_repair import _strip_markdown_fences, parse_with_repair
        cleaned = _strip_markdown_fences(content)
        try:
            return schema.model_validate_json(cleaned)
        except ValidationError:
            data = parse_with_repair(cleaned)
            return schema.model_validate(data)

    @staticmethod
    def _corrective(user: str, last_error: Exception | None) -> str:
        note = (
            "\n\nYour previous response did not match the required JSON schema. "
            "Return ONLY a JSON object that satisfies the schema — no prose, "
            "no markdown fences."
        )
        if last_error is not None:
            note += f" First error: {str(last_error)[:200]}"
        return user + note
