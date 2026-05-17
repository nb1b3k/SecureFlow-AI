"""Content-addressed filesystem cache for LLM responses.

Key includes `prompt_version`, so editing a prompt invalidates only its
own cache entries. Cache values are JSON; the wrapping client is responsible
for revalidating the JSON against the original Pydantic schema on read.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_DIR = ".secureflow_cache/llm"


def _key(
    *,
    prompt_version: str,
    model: str,
    temperature: float,
    system: str,
    user: str,
) -> str:
    h = hashlib.sha256()
    h.update(prompt_version.encode("utf-8"))
    h.update(b"|")
    h.update(model.encode("utf-8"))
    h.update(b"|")
    h.update(f"{temperature:.4f}".encode())
    h.update(b"|")
    h.update(hashlib.sha256(system.encode("utf-8")).hexdigest().encode("utf-8"))
    h.update(b"|")
    h.update(hashlib.sha256(user.encode("utf-8")).hexdigest().encode("utf-8"))
    return h.hexdigest()


class ContentAddressedCache:
    """A small JSON-on-disk cache keyed by SHA-256 of (prompt + inputs)."""

    def __init__(self, root: str | Path = DEFAULT_DIR, *, enabled: bool = True) -> None:
        self.root = Path(root)
        self.enabled = enabled

    def _path_for(self, key: str) -> Path:
        return self.root / key[:2] / f"{key[2:]}.json"

    def get(
        self,
        *,
        prompt_version: str,
        model: str,
        temperature: float,
        system: str,
        user: str,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        path = self._path_for(_key(
            prompt_version=prompt_version, model=model,
            temperature=temperature, system=system, user=user,
        ))
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def put(
        self,
        *,
        prompt_version: str,
        model: str,
        temperature: float,
        system: str,
        user: str,
        value: dict[str, Any],
    ) -> None:
        # We always write — even when reads are disabled — so a future enabled
        # read can find prior results. Disabling reads is the more common
        # "no-cache" intent than refusing to write.
        path = self._path_for(_key(
            prompt_version=prompt_version, model=model,
            temperature=temperature, system=system, user=user,
        ))
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False)
        os.replace(tmp, path)

    def clear(self) -> int:
        """Remove all cached entries. Returns the number of files deleted."""
        if not self.root.exists():
            return 0
        removed = 0
        for p in self.root.rglob("*.json"):
            try:
                p.unlink()
                removed += 1
            except OSError:
                pass
        return removed
