"""Ollama LLM client — talks to a local Ollama server over HTTP.

Ollama runs llama.cpp under the hood, which is the best CPU-only inference
path for users without a GPU. On Windows + AMD APU this is the only viable
local-LLM route (no CUDA, no ROCm on Windows for that hardware).

Endpoint: `POST http://localhost:11434/api/chat`. We pin `stream=false`
so we get one final JSON body per call. Structured outputs use Ollama's
`format` field — passing a JSON Schema works on modern Ollama (>=0.5).

Cache + budget plumbing mirrors GeminiClient. Per-minute rate limiting
isn't a concern locally, so we skip the failover/cooldown logic.
"""

from __future__ import annotations

import json
import os
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

log = get_logger("llm.ollama")
T = TypeVar("T", bound=BaseModel)


DEFAULT_HOST = "http://localhost:11434"
# Local inference can be slow on a 4-core CPU; allow plenty of time for
# a single response.
REQUEST_TIMEOUT_SECONDS = 300


class OllamaClient(LLMClient):
    """LLMClient backed by a local Ollama daemon."""

    name = "ollama"

    def __init__(
        self,
        *,
        model: str = "qwen2.5-coder:3b",
        host: str | None = None,
        cache: ContentAddressedCache | None = None,
        budget: BudgetTracker | None = None,
    ) -> None:
        self.model = model
        self.host = (host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")
        self._cache = cache
        self._budget = budget
        log.info("ollama client ready", extra={"model": self.model, "host": self.host})

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

        # 2. Budget reservation
        if self._budget is not None:
            self._budget.reserve(estimated_tokens=max_tokens)

        # 3. Call + parse, with one corrective retry on schema failure.
        last_error: Exception | None = None
        validation_retries = 0
        for attempt in range(2):
            try:
                content, tokens_in, tokens_out, latency_ms = self._call_ollama(
                    system=system_masked,
                    user=(user_masked if attempt == 0 else self._corrective_followup(
                        user_masked, last_error
                    )),
                    schema=schema,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                if self._budget is not None:
                    self._budget.record(tokens_in=tokens_in, tokens_out=tokens_out)
                try:
                    parsed = self._validate(content, schema)
                except (ValidationError, json.JSONDecodeError) as ve:
                    # Malformed JSON and schema-mismatch are both "the model
                    # didn't follow the schema" — count both as validation
                    # retries so the corrective follow-up kicks in.
                    last_error = ve
                    validation_retries += 1
                    log.warning(
                        "ollama response failed schema validation (attempt %d): %s",
                        attempt + 1,
                        ve.errors()[:2] if isinstance(ve, ValidationError) else str(ve)[:200],
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
            except Exception as e:
                last_error = e
                log.warning("ollama call failed (attempt %d): %s", attempt + 1, e)
                continue

        raise LLMValidationError(
            f"ollama did not produce a valid {schema.__name__} after retries: {last_error}"
        )

    # ----------------------------------------------------------------- private

    def _call_ollama(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        temperature: float,
        max_tokens: int,
    ) -> tuple[str, int, int, int]:
        """Invoke Ollama once. Returns (content, tokens_in, tokens_out, latency_ms)."""
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # Pass the JSON Schema directly; modern Ollama constrains the
            # output to match. Older versions just use "json" — we send the
            # schema and rely on the model to fill it in correctly; the
            # client's validation step + retry catches malformed output.
            "format": schema.model_json_schema(),
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        url = f"{self.host}/api/chat"
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "secureflow-ai/0.1")

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                pass
            raise LLMError(f"ollama HTTP {e.code}: {body_text}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            raise LLMError(
                f"could not reach Ollama at {self.host}: {e}. "
                f"Is the daemon running? `ollama serve` or the system-tray app."
            ) from e
        elapsed_ms = int((time.monotonic() - start) * 1000)

        message = (payload.get("message") or {})
        content = message.get("content") or ""
        tokens_in = int(payload.get("prompt_eval_count") or 0)
        tokens_out = int(payload.get("eval_count") or 0)
        return content, tokens_in, tokens_out, elapsed_ms

    @staticmethod
    def _validate(content: str, schema: type[T]) -> T:
        """Validate Ollama's text response against the requested schema."""
        cleaned = (content or "").strip()
        # Some models wrap JSON in markdown fences despite format=schema.
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:].lstrip()
            cleaned = cleaned.rstrip("`").strip()
        try:
            return schema.model_validate_json(cleaned)
        except ValidationError:
            data = json.loads(cleaned)
            return schema.model_validate(data)

    @staticmethod
    def _corrective_followup(user: str, last_error: Exception | None) -> str:
        note = (
            "\n\nYour previous response did not match the required JSON schema. "
            "Return ONLY a JSON object that satisfies the schema."
        )
        if last_error is not None:
            note += f" First error: {str(last_error)[:200]}"
        return user + note
