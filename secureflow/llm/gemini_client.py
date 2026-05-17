"""Gemini-backed LLM client.

The v1 default. Uses the `google-genai` SDK with structured-output
(`response_schema`) so the model is constrained to emit valid JSON.

API-key handling: read once from `GEMINI_API_KEY` env at construction time.
The key is never logged, never written to disk, never included in error
messages. Missing key → `ConfigError` at init, not at first call.
"""

from __future__ import annotations

import json
import re
import time
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from secureflow.config import gemini_api_key
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

log = get_logger("llm.gemini")
T = TypeVar("T", bound=BaseModel)


class RateLimitedError(LLMError):
    """Provider returned 429 after all retries were exhausted."""


_RATE_LIMIT_MAX_ATTEMPTS = 2
_RATE_LIMIT_BASE_SLEEP = 2.0  # seconds; multiplied by 2**attempt
# After the client has hit a 429, refuse subsequent calls for this window so
# we don't spend 30s × N findings cycling through retry waits during a
# single rate-limited PR scan. Cleared when the window expires.
_RATE_LIMIT_COOLDOWN_SECONDS = 25
# When Gemini reports the *daily* free-tier cap is exhausted (`limit: 0` on
# `GenerateRequestsPerDayPerProjectPerModel-FreeTier`), retrying within the
# same process is pointless — the quota won't reset until midnight Pacific.
# We trip a long cooldown so the rest of the scan / eval doesn't waste time.
_DAILY_COOLDOWN_SECONDS = 6 * 3600  # 6 hours; the process usually exits sooner.


class ConfigError(RuntimeError):
    """Raised at init when required configuration (e.g., API key) is missing."""


class GeminiClient(LLMClient):
    """The v1 default LLM backend."""

    name = "gemini"

    def __init__(
        self,
        *,
        model: str = "gemini-2.0-flash-lite",
        fallback_models: list[str] | None = None,
        cache: ContentAddressedCache | None = None,
        budget: BudgetTracker | None = None,
    ) -> None:
        key = gemini_api_key()
        if not key:
            raise ConfigError(
                "GEMINI_API_KEY is not set. Copy .env.example to .env and fill in "
                "your key (get one at https://aistudio.google.com/apikey)."
            )
        self.model = model
        # Remaining models to try when the primary returns daily-cap. We pop
        # from this list as we attempt failovers, so it shrinks across the
        # run — preventing a tight loop if every fallback is also capped.
        self.fallback_models: list[str] = list(fallback_models or [])
        self._cache = cache
        self._budget = budget
        self._rate_limited_until: float = 0.0
        # Lazy import so the package imports even when google-genai isn't installed.
        try:
            from google import genai  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover - dep guard
            raise ConfigError(
                "google-genai not installed. Run `py -m pip install google-genai`."
            ) from e
        self._client = genai.Client(api_key=key)
        log.info("gemini client ready", extra={"model": self.model})

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
        # Mask any secrets in the inputs before they leave the process.
        system_masked = mask(system)
        user_masked = mask(user)

        # 1. Cache lookup
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
                except (KeyError, ValidationError):
                    parsed = None
                if parsed is not None:
                    return LLMCallResult[T](
                        parsed=parsed,
                        prompt_version=prompt_version,
                        model=self.model,
                        tokens_in=cached.get("tokens_in", 0),
                        tokens_out=cached.get("tokens_out", 0),
                        cache_hit=True,
                        latency_ms=0,
                    )

        # 2. Budget check
        if self._budget is not None:
            self._budget.reserve(estimated_tokens=max_tokens)

        # 3. Call the model, with one corrective retry on schema failure
        last_error: Exception | None = None
        validation_retries = 0
        for attempt in range(2):
            try:
                response, tokens_in, tokens_out, latency_ms = self._call_gemini(
                    system=system_masked,
                    user=user_masked if attempt == 0 else self._corrective_followup(
                        user_masked, last_error
                    ),
                    schema=schema,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                if self._budget is not None:
                    self._budget.record(tokens_in=tokens_in, tokens_out=tokens_out)
                try:
                    parsed = self._parse_response(response, schema)
                except ValidationError as ve:
                    last_error = ve
                    validation_retries += 1
                    log.warning(
                        "gemini response failed schema validation (attempt %d): %s",
                        attempt + 1, ve.errors()[:2] if ve.errors() else ve,
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
                    model=self.model,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    cache_hit=False,
                    latency_ms=latency_ms,
                    validation_retries=validation_retries,
                )
            except (LLMValidationError, LLMError):
                raise
            except Exception as e:  # network/SDK errors
                last_error = e
                log.warning("gemini call failed (attempt %d): %s", attempt + 1, e)
                continue

        raise LLMValidationError(
            f"gemini call did not produce a valid {schema.__name__} after retries: {last_error}"
        )

    # ----------------------------------------------------------------- private

    def _call_gemini(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        temperature: float,
        max_tokens: int,
    ) -> tuple[object, int, int, int]:
        """Invoke the Gemini SDK once with rate-limit retries.

        Honors the `retryDelay` hint when the provider sends one; otherwise
        applies exponential backoff. After `_RATE_LIMIT_MAX_ATTEMPTS` 429s,
        raises `RateLimitedError` which the caller treats as a normal LLM
        failure (per-finding skip, pipeline continues).
        """
        from google.genai import types  # type: ignore[import-not-found]

        cfg = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_schema=schema,
            temperature=temperature,
            max_output_tokens=max_tokens,
        )

        # Fast-fail if we've recently hit a 429 — avoids burning 30s per
        # call during a rate-limited run.
        if self._rate_limited_until > time.monotonic():
            raise RateLimitedError(
                f"gemini in cooldown until {self._rate_limited_until - time.monotonic():.0f}s "
                "have elapsed (set per-client to dodge unbroken backoff stalls)"
            )

        start = time.monotonic()
        last_429: Exception | None = None
        resp = None

        # Outer loop: one iteration per (current model). When the current
        # model returns daily-cap we attempt a failover and the outer loop
        # restarts against the new model with a fresh retry budget. Without
        # this restart, _RATE_LIMIT_MAX_ATTEMPTS would cap *total models
        # tried* instead of *retries per model*.
        while resp is None:
            daily_capped = False
            for attempt in range(_RATE_LIMIT_MAX_ATTEMPTS):
                try:
                    resp = self._client.models.generate_content(
                        model=self.model, contents=user, config=cfg,
                    )
                    break
                except Exception as e:
                    if not _is_rate_limit(e):
                        raise
                    last_429 = e
                    if _is_daily_exhausted(e):
                        daily_capped = True
                        break
                    wait = _parse_retry_delay(e) or (
                        _RATE_LIMIT_BASE_SLEEP * (2 ** attempt)
                    )
                    log.warning(
                        "gemini 429 on %s (attempt %d/%d); sleeping %.1fs",
                        self.model, attempt + 1, _RATE_LIMIT_MAX_ATTEMPTS, wait,
                    )
                    time.sleep(wait)

            if resp is not None:
                break

            if daily_capped and self._failover():
                continue  # outer-loop restart against new model

            if daily_capped:
                self._rate_limited_until = time.monotonic() + _DAILY_COOLDOWN_SECONDS
                log.warning(
                    "gemini daily quota exhausted on %s; no fallback models left",
                    self.model,
                )
                raise RateLimitedError(
                    f"gemini daily free-tier quota exhausted: {str(last_429)[:200]}"
                )
            self._rate_limited_until = time.monotonic() + _RATE_LIMIT_COOLDOWN_SECONDS
            raise RateLimitedError(
                f"gemini rate limit not cleared after {_RATE_LIMIT_MAX_ATTEMPTS} attempts: {last_429}"
            )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        usage = getattr(resp, "usage_metadata", None)
        tokens_in = int(getattr(usage, "prompt_token_count", 0) or 0)
        tokens_out = int(getattr(usage, "candidates_token_count", 0) or 0)
        return resp, tokens_in, tokens_out, elapsed_ms

    def _failover(self) -> bool:
        """Pop the next fallback model into `self.model`. Returns True on success.

        Returns False when the fallback list is empty — caller should give
        up and raise RateLimitedError. We pop rather than peek so a model
        that *also* hits daily cap on its next call falls through to the
        one after it, not back to itself in a tight loop.
        """
        if not self.fallback_models:
            return False
        prev = self.model
        self.model = self.fallback_models.pop(0)
        log.warning("gemini failover %s -> %s (primary daily-capped)", prev, self.model)
        return True

    def _parse_response(self, response: object, schema: type[T]) -> T:
        """Pull JSON out of a Gemini response and validate it."""
        # Prefer .parsed if the SDK already parsed it.
        parsed_obj = getattr(response, "parsed", None)
        if parsed_obj is not None and isinstance(parsed_obj, schema):
            return parsed_obj
        text = getattr(response, "text", None) or ""
        if not text:
            raise ValidationError.from_exception_data(
                title=schema.__name__,
                line_errors=[
                    {"type": "missing", "loc": ("",), "msg": "empty response"}
                ],
            )
        # response.text may already be JSON; if it's wrapped in code fences, strip them.
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:].lstrip()
        try:
            return schema.model_validate_json(cleaned)
        except ValidationError:
            # As a last resort, parse-then-validate to tolerate trailing junk.
            data = json.loads(cleaned)
            return schema.model_validate(data)

    @staticmethod
    def _corrective_followup(user: str, last_error: Exception | None) -> str:
        """Inline a short corrective notice for the retry attempt."""
        note = (
            "\n\nYour previous response did not match the required JSON schema. "
            "Return ONLY the JSON object that satisfies the schema."
        )
        if last_error is not None:
            # Include only the first error path to keep tokens low.
            note += f" First error: {str(last_error)[:200]}"
        return user + note


# ────────────────────────────────────────────────────── rate-limit helpers ──


def _is_rate_limit(exc: Exception) -> bool:
    """Detect a Gemini 429 across SDK versions without coupling to internals."""
    msg = str(exc)
    if "429" in msg:
        return True
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if status == 429:
        return True
    return "RESOURCE_EXHAUSTED" in msg


_RETRY_DELAY_RE = re.compile(r"retryDelay[\"']?\s*:\s*[\"']?(\d+(?:\.\d+)?)s")


def _parse_retry_delay(exc: Exception) -> float | None:
    """Pull the `retryDelay: Ns` hint out of a Gemini 429 error if present."""
    m = _RETRY_DELAY_RE.search(str(exc))
    if m:
        try:
            return min(30.0, float(m.group(1)))  # clamp to 30s sanity ceiling
        except ValueError:
            return None
    return None


def _is_daily_exhausted(exc: Exception) -> bool:
    """Distinguish a per-day cap (won't reset before midnight Pacific) from a
    transient per-minute throttle (clears in ~30s).

    Gemini's 429 payload includes a `quotaId` of either
    `GenerateRequestsPerMinutePerProjectPerModel-FreeTier` or
    `GenerateRequestsPerDayPerProjectPerModel-FreeTier`. When the daily
    quota is the one that fired AND `limit: 0` shows up (Google zeroes the
    free-tier daily allowance once exhausted), we should fail-fast for the
    rest of this process.
    """
    msg = str(exc)
    if "GenerateRequestsPerDayPerProjectPerModel" not in msg:
        return False
    return "limit: 0" in msg or "limit:0" in msg
