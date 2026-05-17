"""OpenRouter LLM client — OpenAI-compatible meta-API gateway.

OpenRouter aggregates 100+ models behind one OpenAI-compatible endpoint.
The `:free` suffix selects free-tier routes (typically 20 RPM and 50 RPD
on free models, per provider attribution rules). Useful as a last-resort
fallback when Gemini AND Groq daily/per-minute quotas are exhausted.

Endpoint:  POST https://openrouter.ai/api/v1/chat/completions
Auth:      Authorization: Bearer ${OPENROUTER_AI_API_KEY}
Optional:  HTTP-Referer + X-Title headers improve attribution and
           sometimes unlock slightly better rate limits.

Architecture mirrors GroqClient: corrective-retry on schema validation,
shared-state cooldown so concurrent instances don't burst, 429 sets the
cooldown using the response's `retry-after` if present.
"""

from __future__ import annotations

import json
import threading
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

log = get_logger("llm.openrouter")
T = TypeVar("T", bound=BaseModel)

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
REQUEST_TIMEOUT_SECONDS = 120

# Free OpenRouter routes are typically capped at 20 RPM. 3.5s/call =
# 17 RPM, comfortably under the cap with margin for the per-request
# latency that consumes wall-clock time.
_MIN_GAP_SECONDS = 3.5
_DEFAULT_BACKOFF_SECONDS = 12.0

# Shared throttle across all OpenRouterClient instances in this process,
# so two concurrent agents holding separate clients don't each enforce
# the gap independently and burst the per-minute cap. Same pattern as
# GroqClient.
_SHARED_LOCK = threading.Lock()
_SHARED_LAST_CALL_AT: float = 0.0
_SHARED_RATE_LIMITED_UNTIL: float = 0.0


class OpenRouterRateLimitedError(LLMError):
    """OpenRouter returned 429."""


class OpenRouterConfigError(LLMError):
    """Missing API key or unauthorised."""


class OpenRouterClient(LLMClient):
    """LLMClient backed by OpenRouter's OpenAI-compatible API."""

    name = "openrouter"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "deepseek/deepseek-v4-flash:free",
        fallback_models: list[str] | None = None,
        cache: ContentAddressedCache | None = None,
        budget: BudgetTracker | None = None,
        http_referer: str = "https://github.com/nb1b3k/secureflow-ai",
        x_title: str = "SecureFlow AI",
    ) -> None:
        if not api_key:
            raise OpenRouterConfigError(
                "OPENROUTER_AI_API_KEY is not set. Get one free at "
                "https://openrouter.ai/settings/keys and put it in .env."
            )
        self._api_key = api_key
        self.model = model
        self.fallback_models: list[str] = list(fallback_models or [])
        self._cache = cache
        self._budget = budget
        self._http_referer = http_referer
        self._x_title = x_title
        self._last_call_at: float = 0.0
        self._rate_limited_until: float = 0.0
        log.info("openrouter client ready", extra={"model": self.model})

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
                    pass

        if self._budget is not None:
            self._budget.reserve(estimated_tokens=max_tokens)

        last_error: Exception | None = None
        validation_retries = 0
        for attempt in range(2):
            try:
                content, tokens_in, tokens_out, latency_ms, served_by = self._call_openrouter(
                    system=system_masked,
                    user=user_masked if attempt == 0 else self._corrective(user_masked, last_error),
                    schema=schema,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except (OpenRouterRateLimitedError, OpenRouterConfigError):
                raise
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
                    "openrouter response failed schema validation (attempt %d): %s",
                    attempt + 1, str(ve)[:200],
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
            f"openrouter did not produce a valid {schema.__name__} after retries: {last_error}"
        )

    # ─────────────────────────────────────────────────────── helpers ──

    def _throttle(self) -> None:
        """Per-call gap is honoured (sleep); cooldown after a 429 fast-fails
        (raise) so the chain can skip ahead to the next provider instead
        of stalling on this one. Same shape as `GroqClient._throttle`.
        """
        global _SHARED_LAST_CALL_AT, _SHARED_RATE_LIMITED_UNTIL
        with _SHARED_LOCK:
            now = time.monotonic()
            if now < _SHARED_RATE_LIMITED_UNTIL:
                wait_left = _SHARED_RATE_LIMITED_UNTIL - now
                self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL
                raise OpenRouterRateLimitedError(
                    f"rate_limited: openrouter in cooldown for another {wait_left:.1f}s "
                    "(set per-client to dodge unbroken backoff stalls)"
                )
            gap = now - _SHARED_LAST_CALL_AT
            if gap < _MIN_GAP_SECONDS:
                time.sleep(_MIN_GAP_SECONDS - gap)
            _SHARED_LAST_CALL_AT = time.monotonic()
            self._last_call_at = _SHARED_LAST_CALL_AT
            self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL

    def _call_openrouter(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        temperature: float,
        max_tokens: int,
    ) -> tuple[str, int, int, int, str | None]:
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
            OPENROUTER_ENDPOINT,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
        )
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "secureflow-ai/0.1")
        # OpenRouter uses these for attribution + sometimes better limits.
        req.add_header("HTTP-Referer", self._http_referer)
        req.add_header("X-Title", self._x_title)

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            if e.code == 429:
                retry_after = float(e.headers.get("retry-after") or _DEFAULT_BACKOFF_SECONDS)
                global _SHARED_RATE_LIMITED_UNTIL
                with _SHARED_LOCK:
                    _SHARED_RATE_LIMITED_UNTIL = max(
                        _SHARED_RATE_LIMITED_UNTIL,
                        time.monotonic() + retry_after,
                    )
                    self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL
                self._maybe_rotate_model(err_body)
                raise OpenRouterRateLimitedError(
                    f"rate_limited: openrouter 429 (retry-after={retry_after:.1f}s): {err_body[:300]}"
                ) from e
            if e.code in (401, 403):
                raise OpenRouterConfigError(
                    f"openrouter auth failed ({e.code}). Check OPENROUTER_AI_API_KEY."
                ) from e
            raise LLMError(f"openrouter HTTP {e.code}: {err_body[:400]}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMError(f"could not reach OpenRouter: {e}") from e

        elapsed_ms = int((time.monotonic() - start) * 1000)
        choices = payload.get("choices") or []
        if not choices:
            # OpenRouter sometimes returns errors in the body even on 200.
            err = payload.get("error") or {}
            if err:
                msg = err.get("message", "")
                if "rate" in msg.lower() or "limit" in msg.lower():
                    raise OpenRouterRateLimitedError(f"rate_limited: openrouter inline error: {msg[:300]}")
                raise LLMError(f"openrouter inline error: {msg[:300]}")
            raise LLMError(f"openrouter returned no choices: {str(payload)[:400]}")
        content = ((choices[0].get("message") or {}).get("content")) or ""
        usage = payload.get("usage") or {}
        tokens_in = int(usage.get("prompt_tokens") or 0)
        tokens_out = int(usage.get("completion_tokens") or 0)
        served_by = payload.get("model")
        return content, tokens_in, tokens_out, elapsed_ms, served_by

    def _maybe_rotate_model(self, err_body: str) -> None:
        low = err_body.lower()
        looks_daily = "per day" in low or "daily" in low or "rpd" in low
        if looks_daily and self.fallback_models:
            new_model = self.fallback_models.pop(0)
            log.warning(
                "openrouter daily quota exhausted on %s; rotating to %s",
                self.model, new_model,
            )
            self.model = new_model
            self._rate_limited_until = 0.0

    @staticmethod
    def _validate(content: str, schema: type[T]) -> T:
        """Parse the model's text response and validate against the schema.

        Uses the shared `parse_with_repair` fallback so almost-valid JSON
        (free OpenRouter models occasionally drop a closing quote)
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
