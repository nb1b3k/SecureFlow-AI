"""Deterministic policy engine — turns findings into a Decision.

The policy engine is intentionally pure Python. LLM output is advisory;
PASS / WARN / FAIL is always computed deterministically.
"""

from secureflow.policy.policy_engine import decide

__all__ = ["decide"]
