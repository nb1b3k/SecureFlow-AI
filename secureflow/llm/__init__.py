"""LLM provider abstraction.

Five concrete backends ship: DeepSeek (paid, primary), Gemini (free),
Groq (free), OpenRouter (free), and Ollama (local). All five implement
the same `LLMClient.complete` contract and are wired into a chain
failover by the factory. See `design/01_llm_stack.md` for the full design.
"""

from secureflow.llm.base import LLMCallResult, LLMClient, LLMError, LLMValidationError
from secureflow.llm.budget import BudgetExceededError, BudgetTracker
from secureflow.llm.cache import ContentAddressedCache
from secureflow.llm.registry import PromptRegistry, PromptSpec

__all__ = [
    "BudgetExceededError",
    "BudgetTracker",
    "ContentAddressedCache",
    "LLMCallResult",
    "LLMClient",
    "LLMError",
    "LLMValidationError",
    "PromptRegistry",
    "PromptSpec",
]
