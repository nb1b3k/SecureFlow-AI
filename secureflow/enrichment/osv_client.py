"""OSV API client — enrich CVE/GHSA findings with extra details.

OSV is open (no auth) and generous on rate limits. We use two endpoints:
- `POST /v1/query`         — vuln list for `{package, version}`
- `GET  /v1/vulns/<id>`    — full details for one CVE/GHSA ID

This client is best-effort. Network errors / HTTP 5xx / rate limits cause
the enrichment to skip silently (logged at WARN). The finding keeps
whatever it already had.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from secureflow.enrichment.cache import EnrichmentCache
from secureflow.utils.logging import get_logger

log = get_logger("enrich.osv")

OSV_BASE = "https://api.osv.dev"
USER_AGENT = "secureflow-ai/0.1 (enrichment)"
TIMEOUT_SECONDS = 6


class OsvClient:
    """Best-effort OSV enrichment."""

    def __init__(self, *, cache: EnrichmentCache | None = None, enabled: bool = True) -> None:
        self.cache = cache or EnrichmentCache()
        self.enabled = enabled

    # ─────────────────────────────────────────────────────────── public API

    def lookup_id(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch one vulnerability record by CVE/GHSA/OSV ID."""
        if not self.enabled or not vuln_id:
            return None
        cached = self.cache.get("osv-id", vuln_id)
        if cached is not None:
            log.debug("osv cache hit", extra={"vuln_id": vuln_id})
            return cached
        url = f"{OSV_BASE}/v1/vulns/{vuln_id}"
        data = self._http_get_json(url)
        if data is None:
            return None
        self.cache.put("osv-id", vuln_id, data)
        return data

    def query_package(self, *, name: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
        """List vulnerabilities for a `package@version` in the given ecosystem."""
        if not self.enabled or not name or not version:
            return []
        key = f"{ecosystem}|{name}|{version}"
        cached = self.cache.get("osv-query", key)
        if cached is not None and "vulns" in cached:
            return list(cached.get("vulns") or [])
        body = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        data = self._http_post_json(f"{OSV_BASE}/v1/query", body)
        if data is None:
            return []
        self.cache.put("osv-query", key, data)
        return list(data.get("vulns") or [])

    # ─────────────────────────────────────────────────────────── helpers

    def _http_get_json(self, url: str) -> dict[str, Any] | None:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "application/json")
        return self._send(req, op="GET", url=url)

    def _http_post_json(self, url: str, body: dict) -> dict[str, Any] | None:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        return self._send(req, op="POST", url=url)

    @staticmethod
    def _send(req: urllib.request.Request, *, op: str, url: str) -> dict[str, Any] | None:
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                log.debug("osv 404", extra={"url": url})
                return None
            log.warning("osv %s failed: %s", op, e, extra={"url": url, "status": e.code})
            return None
        except (urllib.error.URLError, TimeoutError) as e:
            log.warning("osv %s network error: %s", op, e, extra={"url": url})
            return None
        except json.JSONDecodeError:
            log.warning("osv %s returned non-JSON", op, extra={"url": url})
            return None
        elapsed_ms = int((time.monotonic() - start) * 1000)
        log.debug("osv %s ok", op, extra={"url": url, "latency_ms": elapsed_ms})
        return payload if isinstance(payload, dict) else None
