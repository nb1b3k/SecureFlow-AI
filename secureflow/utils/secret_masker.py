"""Mask secret-like substrings in any text before it is logged or sent to an LLM.

We never want to:
- print full secrets in reports or logs,
- send unmasked secrets to a third-party LLM,
- echo the user's own configured API key in error messages.

The mask preserves a short prefix/suffix and includes a stable hash suffix so
two different secrets in the same text remain distinguishable to the reader
(and to the model) without exposing their values.

This is intentionally a thin, fast layer. Gitleaks is the real secret scanner.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS_SECRET_KEY", re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OPENAI_API_KEY", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{40,}\b")),
    ("STRIPE_LIVE_KEY", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
]


@dataclass(frozen=True)
class MaskHit:
    """One match the masker rewrote."""

    kind: str
    span: tuple[int, int]


def _hash8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def _mask_value(raw: str, kind: str) -> str:
    """Produce a stable redacted token for `raw`."""
    if len(raw) <= 8:
        return f"<REDACTED_{kind}_{_hash8(raw)}>"
    head = raw[:4]
    tail = raw[-4:]
    return f"{head}****{tail}<{kind}:{_hash8(raw)}>"


def mask(text: str) -> str:
    """Return `text` with any detected secrets replaced by a masked token."""
    if not text:
        return text
    out = text
    for kind, pat in _PATTERNS:
        out = pat.sub(lambda m, k=kind: _mask_value(m.group(0), k), out)
    return out


def find_hits(text: str) -> list[MaskHit]:
    """Return the list of secret-like matches without rewriting `text`.

    Useful for telling a reviewer "the scanner saw these but did not log them".
    """
    hits: list[MaskHit] = []
    for kind, pat in _PATTERNS:
        for m in pat.finditer(text or ""):
            hits.append(MaskHit(kind=kind, span=m.span()))
    return hits


def mask_iter(items: Iterable[str]) -> list[str]:
    """Convenience: mask each item in an iterable."""
    return [mask(s) for s in items]
