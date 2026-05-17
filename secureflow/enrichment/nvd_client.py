"""NVD API client — fetch CVSS scores and rich descriptions for CVE IDs.

API endpoint: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`

Auth: optional. With no API key, NVD rate-limits at ~5 requests / 30s.
With a key (free from https://nvd.nist.gov/developers/request-an-api-key),
the limit is ~50/30s. The key is read from `NVD_API_KEY` env at init.

This client is best-effort: errors / rate-limits never break the pipeline.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from secureflow.enrichment.cache import EnrichmentCache
from secureflow.utils.logging import get_logger

log = get_logger("enrich.nvd")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "secureflow-ai/0.1 (enrichment)"
TIMEOUT_SECONDS = 5  # NVD free tier is slow; keep the cap tight so enrichment can't stall.
# Free unauthed: 5 req / 30s = 6s spacing. With key: 50/30s = 0.6s.
_UNAUTHED_SPACING = 6.5
_AUTHED_SPACING = 0.7


class NvdClient:
    """Best-effort NVD enrichment for single CVE IDs."""

    def __init__(self, *, cache: EnrichmentCache | None = None, enabled: bool = True) -> None:
        self.cache = cache or EnrichmentCache()
        self.enabled = enabled
        self.api_key = os.environ.get("NVD_API_KEY") or None
        self._last_call: float = 0.0

    def lookup_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Return a compact normalized dict for one CVE, or None on miss/error.

        Result shape:
            {
              "id": "CVE-xxxx-yyyy",
              "description": str,
              "cvss_score": float | None,
              "cvss_vector": str | None,
              "cwes": list[str],
              "published": str | None,
              "references": list[str],
            }
        """
        if not self.enabled or not cve_id or not cve_id.startswith("CVE-"):
            return None
        cached = self.cache.get("nvd", cve_id)
        if cached is not None:
            log.debug("nvd cache hit", extra={"cve_id": cve_id})
            return cached
        self._respect_rate_limit()
        raw = self._fetch(cve_id)
        if raw is None:
            return None
        normalized = self._normalize(raw, cve_id)
        if normalized is not None:
            self.cache.put("nvd", cve_id, normalized)
        return normalized

    # ─────────────────────────────────────────────────────────── helpers

    def _respect_rate_limit(self) -> None:
        spacing = _AUTHED_SPACING if self.api_key else _UNAUTHED_SPACING
        gap = time.monotonic() - self._last_call
        if gap < spacing:
            time.sleep(spacing - gap)

    def _fetch(self, cve_id: str) -> dict[str, Any] | None:
        url = f"{NVD_BASE}?cveId={urllib.parse.quote(cve_id)}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "application/json")
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            log.warning("nvd lookup failed: %s", e, extra={"cve_id": cve_id, "status": e.code})
            return None
        except (urllib.error.URLError, TimeoutError) as e:
            log.warning("nvd network error: %s", e, extra={"cve_id": cve_id})
            return None
        except json.JSONDecodeError:
            log.warning("nvd non-JSON response", extra={"cve_id": cve_id})
            return None
        finally:
            self._last_call = time.monotonic()
        elapsed_ms = int((time.monotonic() - start) * 1000)
        log.debug("nvd ok", extra={"cve_id": cve_id, "latency_ms": elapsed_ms})
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _normalize(raw: dict, cve_id: str) -> dict[str, Any] | None:
        try:
            vulnerabilities = raw.get("vulnerabilities") or []
            if not vulnerabilities:
                return None
            cve = vulnerabilities[0].get("cve", {})

            description = ""
            for desc in cve.get("descriptions") or []:
                if desc.get("lang") == "en":
                    description = desc.get("value") or ""
                    break

            score: float | None = None
            vector: str | None = None
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                items = metrics.get(key) or []
                if items:
                    cvss = items[0].get("cvssData") or {}
                    score = cvss.get("baseScore")
                    vector = cvss.get("vectorString")
                    break

            cwes: list[str] = []
            for weakness in cve.get("weaknesses") or []:
                for desc in weakness.get("description") or []:
                    val = desc.get("value")
                    if isinstance(val, str) and val.startswith("CWE-"):
                        cwes.append(val)

            refs = [
                r.get("url")
                for r in (cve.get("references") or [])
                if isinstance(r, dict) and r.get("url")
            ][:5]

            return {
                "id": cve_id,
                "description": description,
                "cvss_score": float(score) if score is not None else None,
                "cvss_vector": vector,
                "cwes": cwes,
                "published": cve.get("published"),
                "references": refs,
            }
        except (KeyError, TypeError, ValueError) as e:
            log.debug("nvd parse error", extra={"cve_id": cve_id, "err": str(e)})
            return None
