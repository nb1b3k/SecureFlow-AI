"""Stable finding-ID computation.

A finding's ID must:
- be the same when the same issue is reported across re-pushes,
- survive whitespace / comment / variable-rename edits,
- change when the underlying structure of the code changes.

This lets the PR commenter update its existing comment instead of spamming
a new one on every push, and lets the patch-validation loop confirm that a
finding has actually been removed (rather than just renumbered).
"""

from __future__ import annotations

import hashlib
import re

_WHITESPACE_RUN = re.compile(r"\s+")
_PYTHON_COMMENT = re.compile(r"#.*$", re.MULTILINE)
_C_LIKE_COMMENT = re.compile(r"//.*$", re.MULTILINE)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'")
_SLUG_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalize_path(p: str) -> str:
    """Lightly normalize a file path; preserve case (case-sensitive FS)."""
    if not p:
        return ""
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _slug(text: str, max_words: int = 6) -> str:
    """Slugify a title for use as a fallback rule_id."""
    words = _SLUG_NON_ALNUM.sub(" ", text.lower()).split()
    return "_".join(words[:max_words])


def _line_signature(
    symbol: str | None, start_line: int | None, end_line: int | None
) -> str:
    """Prefer symbol-based signature; fall back to line-range."""
    if symbol:
        return symbol
    if start_line is not None:
        return f"L{start_line}-{end_line if end_line is not None else start_line}"
    return "L?"


def code_fingerprint(code: str) -> str:
    """Hash code in a way that ignores whitespace, comments, and string contents.

    Used as the last component of a finding ID so that:
    - swapping a secret value in the same structure → same ID,
    - reformatting whitespace → same ID,
    - changing structure (e.g., applying a real fix) → different ID.

    Returns the first 8 hex chars of SHA-256.
    """
    if not code:
        return "0" * 8
    s = _BLOCK_COMMENT.sub(" ", code)
    s = _PYTHON_COMMENT.sub("", s)
    s = _C_LIKE_COMMENT.sub("", s)
    s = _STRING_LITERAL.sub('"_"', s)
    s = _WHITESPACE_RUN.sub(" ", s).strip()
    if not s:
        return "0" * 8
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def compute_finding_id(
    *,
    source: str,
    title: str,
    file_path: str | None,
    rule_id: str | None = None,
    symbol: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
    code: str = "",
) -> str:
    """Compute the stable, 16-hex-char ID for a finding.

    The 16-hex prefix gives 64 bits of entropy — plenty for de-dup across a
    single PR's worth of findings, short enough to log readably.
    """
    parts = [
        source,
        rule_id or _slug(title),
        _normalize_path(file_path or ""),
        _line_signature(symbol, start_line, end_line),
        code_fingerprint(code),
    ]
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]
