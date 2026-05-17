"""Simple filesystem cache for enrichment-API responses.

Cache layout: `.secureflow_cache/enrich/<source>/<key>.json`. TTL is set per
source (CVE data is stable; OSV records can change when new fix-versions
are added — we use a longer-than-necessary TTL since stale CVE info is
rarely harmful).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path(".secureflow_cache/enrich")
DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 days


class EnrichmentCache:
    """File-backed JSON cache, TTL'd, atomic writes."""

    def __init__(
        self,
        root: Path | str = DEFAULT_ROOT,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self.root = Path(root)
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled

    def _path_for(self, source: str, key: str) -> Path:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.root / source / h[:2] / f"{h[2:]}.json"

    def get(self, source: str, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        path = self._path_for(source, key)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                envelope = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        if envelope.get("_stored_at", 0) + self.ttl_seconds < time.time():
            return None
        value = envelope.get("value")
        return value if isinstance(value, dict) else None

    def put(self, source: str, key: str, value: dict[str, Any]) -> None:
        path = self._path_for(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        envelope = {"_stored_at": int(time.time()), "value": value}
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(envelope, f, ensure_ascii=False)
        os.replace(tmp, path)
