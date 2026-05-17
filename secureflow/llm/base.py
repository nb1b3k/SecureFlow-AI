"""Abstract LLM client interface.

Every agent that needs an LLM uses `LLMClient.complete(...)`. Concrete
backends (DeepSeek, Gemini, Groq, OpenRouter, Ollama) implement this
contract. Agents never touch a raw model string; they receive
Pydantic-validated results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    """Base class for LLM failures."""


class LLMValidationError(LLMError):
    """The model returned content that failed schema validation after retries."""


class LLMCallResult(BaseModel, Generic[T]):
    """Result of one `LLMClient.complete` call."""

    parsed: T
    prompt_version: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cache_hit: bool = False
    latency_ms: int = 0
    validation_retries: int = 0


class LLMClient(ABC):
    """Provider-agnostic LLM interface."""

    name: str = "abstract"

    @abstractmethod
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
        """Send a single completion and return a validated result.

        Implementations are responsible for:
        - applying the secret masker to `system` and `user` before sending,
        - cache lookup keyed on (prompt_version, model, temperature, system, user),
        - retrying once on validation failure,
        - recording tokens_in/tokens_out and latency_ms,
        - raising `LLMValidationError` after retries are exhausted,
        - raising `LLMError` for other unrecoverable failures.
        """
        raise NotImplementedError
