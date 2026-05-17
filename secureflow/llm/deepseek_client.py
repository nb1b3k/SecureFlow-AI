"""DeepSeek LLM client — OpenAI-compatible paid API, used as last-resort fallback.

Position in the chain: 4th and last link, after the three free-tier providers
(OpenRouter → Groq → Gemini). DeepSeek is a *paid* tier ($5 prepaid, in our
case) so we want to hit it only when every free quota is exhausted — never
as the primary. The chain wires that ordering; this client just exposes the
provider.

Model selection — why `deepseek-chat`, not `deepseek-reasoner`:
  - `deepseek-chat` (V3): $0.27/M input · $1.10/M output. Fast, strong at
    structured JSON, plenty good enough for SecureFlow's evidence-bound
    finding/exploitability/patch prompts.
  - `deepseek-reasoner` (R1): $0.55/M input · $2.19/M output. ~2× the cost
    and adds a chain-of-thought stage that we don't need — our prompts
    already constrain the output to a Pydantic schema. The reasoning
    overhead would burn the $5 budget ~2× faster for marginal quality
    gain on this task type.

At typical SecureFlow per-call sizes (~5K input + ~1K output) `deepseek-chat`
costs about $0.0024 per call → roughly 2000 calls on the $5 budget. That is
a *lot* of runs once OSS-free quotas are exhausted; still, the client errs on
the conservative side with a 1s inter-call gap (~60 RPM client-side cap).

Endpoint:  POST https://api.deepseek.com/v1/chat/completions
Auth:      Authorization: Bearer ${DEEPSEEK_API_KEY}

Architecture mirrors `GroqClient` / `OpenRouterClient`: corrective-retry on
schema validation, shared-process cooldown so concurrent agents don't burst
the limit, 429 honours `retry-after`. The shared throttle keys off this
module's global state — separate from Groq/OpenRouter so a 429 on one
provider doesn't accidentally pause another.
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

log = get_logger("llm.deepseek")
T = TypeVar("T", bound=BaseModel)

DEEPSEEK_ENDPOINT = "https://api.deepseek.com/v1/chat/completions"
REQUEST_TIMEOUT_SECONDS = 120

# Paid tier — DeepSeek does not publish a hard RPM cap but documents
# best-effort throttling under load. 1.0s/call = 60 RPM is well under
# anything we've seen them rate-limit at, and leaves room for parallel
# agents to share the budget. Override via config if you need bursts.
_MIN_GAP_SECONDS = 1.0
_DEFAULT_BACKOFF_SECONDS = 8.0

# Shared throttle across all DeepSeekClient instances in this process,
# same pattern as Groq/OpenRouter — two concurrent agents must not each
# enforce the gap independently and double the effective rate.
_SHARED_LOCK = threading.Lock()
_SHARED_LAST_CALL_AT: float = 0.0
_SHARED_RATE_LIMITED_UNTIL: float = 0.0


class DeepSeekRateLimitedError(LLMError):
    """DeepSeek returned 429 (or its inline-error equivalent)."""


class DeepSeekConfigError(LLMError):
    """Missing API key or 401/403 from the server."""


class DeepSeekClient(LLMClient):
    """LLMClient backed by DeepSeek's OpenAI-compatible API."""

    name = "deepseek"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "deepseek-chat",
        cache: ContentAddressedCache | None = None,
        budget: BudgetTracker | None = None,
    ) -> None:
        if not api_key:
            raise DeepSeekConfigError(
                "DEEPSEEK_API_KEY is not set. Top up at "
                "https://platform.deepseek.com/ and add the key to .env."
            )
        self._api_key = api_key
        self.model = model
        self._cache = cache
        self._budget = budget
        self._last_call_at: float = 0.0
        self._rate_limited_until: float = 0.0
        log.info("deepseek client ready", extra={"model": self.model})

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
                content, tokens_in, tokens_out, latency_ms, served_by = self._call_deepseek(
                    system=system_masked,
                    user=user_masked if attempt == 0 else self._corrective(user_masked, last_error),
                    schema=schema,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except (DeepSeekRateLimitedError, DeepSeekConfigError):
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
                    "deepseek response failed schema validation (attempt %d): %s",
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
            f"deepseek did not produce a valid {schema.__name__} after retries: {last_error}"
        )

    # ─────────────────────────────────────────────────────── helpers ──

    def _throttle(self) -> None:
        """Per-call gap is honoured (sleep); cooldown after a 429 fast-fails
        (raise) so the chain can skip ahead instead of stalling on this link.
        Same shape as `GroqClient._throttle` / `OpenRouterClient._throttle`.

        For DeepSeek specifically the cooldown-then-raise behaviour matters
        less (it's the *last* link in the chain, so there's nothing to skip
        to), but raising still gives the caller a clean failure signal
        instead of an unbounded wall-clock stall.
        """
        global _SHARED_LAST_CALL_AT, _SHARED_RATE_LIMITED_UNTIL
        with _SHARED_LOCK:
            now = time.monotonic()
            if now < _SHARED_RATE_LIMITED_UNTIL:
                wait_left = _SHARED_RATE_LIMITED_UNTIL - now
                self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL
                raise DeepSeekRateLimitedError(
                    f"rate_limited: deepseek in cooldown for another {wait_left:.1f}s"
                )
            gap = now - _SHARED_LAST_CALL_AT
            if gap < _MIN_GAP_SECONDS:
                time.sleep(_MIN_GAP_SECONDS - gap)
            _SHARED_LAST_CALL_AT = time.monotonic()
            self._last_call_at = _SHARED_LAST_CALL_AT
            self._rate_limited_until = _SHARED_RATE_LIMITED_UNTIL

    def _call_deepseek(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        temperature: float,
        max_tokens: int,
    ) -> tuple[str, int, int, int, str | None]:
        schema_str = json.dumps(schema.model_json_schema(), indent=2)
        # DeepSeek's json_object mode requires the word "json" to appear in
        # at least one message — we satisfy it in the system prompt below.
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
            DEEPSEEK_ENDPOINT,
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
                raise DeepSeekRateLimitedError(
                    f"rate_limited: deepseek 429 (retry-after={retry_after:.1f}s): {err_body[:300]}"
                ) from e
            if e.code in (401, 403):
                raise DeepSeekConfigError(
                    f"deepseek auth failed ({e.code}). Check DEEPSEEK_API_KEY."
                ) from e
            if e.code == 402:
                # Out of credit — surface as a config-class error so the chain
                # treats it as "this provider is exhausted, skip" rather than
                # an unrecoverable bug. There's no link after deepseek in our
                # chain, but the error message still has to be actionable.
                raise DeepSeekConfigError(
                    f"deepseek insufficient balance (402). Top up at "
                    f"https://platform.deepseek.com/ — body: {err_body[:200]}"
                ) from e
            raise LLMError(f"deepseek HTTP {e.code}: {err_body[:400]}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMError(f"could not reach DeepSeek: {e}") from e

        elapsed_ms = int((time.monotonic() - start) * 1000)
        choices = payload.get("choices") or []
        if not choices:
            err = payload.get("error") or {}
            if err:
                msg = err.get("message", "")
                if "rate" in msg.lower() or "limit" in msg.lower() or "quota" in msg.lower():
                    raise DeepSeekRateLimitedError(f"rate_limited: deepseek inline error: {msg[:300]}")
                raise LLMError(f"deepseek inline error: {msg[:300]}")
            raise LLMError(f"deepseek returned no choices: {str(payload)[:400]}")
        content = ((choices[0].get("message") or {}).get("content")) or ""
        usage = payload.get("usage") or {}
        tokens_in = int(usage.get("prompt_tokens") or 0)
        tokens_out = int(usage.get("completion_tokens") or 0)
        served_by = payload.get("model")
        return content, tokens_in, tokens_out, elapsed_ms, served_by

    @staticmethod
    def _validate(content: str, schema: type[T]) -> T:
        """Parse the model's text response and validate against the schema.

        Three-step recovery:
          1. Strict JSON via pydantic (fast path; >95% of clean responses).
          2. Strict `json.loads` + pydantic validate (catches schema-only
             issues vs syntax-only).
          3. `parse_with_repair` — recovers from almost-valid JSON
             (missing key quotes, unterminated strings near max_tokens,
             missing commas). See `_json_repair.py` for the rationale.
             Eliminates an LLM corrective-retry on each minor JSON
             error and works across all providers.
        """
        from secureflow.llm._json_repair import _strip_markdown_fences, parse_with_repair
        cleaned = _strip_markdown_fences(content)
        try:
            return schema.model_validate_json(cleaned)
        except ValidationError:
            # Pydantic's model_validate_json fast path fails — try
            # plain parse + repair fallback before giving up.
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
