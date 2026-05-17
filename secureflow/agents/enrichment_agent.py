"""Enrichment agent — supplements findings with external-API metadata.

Runs after threat_map and before reachability_filter. Best-effort: when
APIs are down or rate-limited, the finding keeps whatever it had.

What we add:
- For findings with a CVE ID: NVD's CVSS score + clean English description
  + extra CWE associations; OSV's references and additional advisories.
- For all findings: MITRE ATT&CK techniques implied by their CWEs.

Cost: zero LLM tokens. Two HTTP APIs (cached), no auth needed for the
default unauthed tier.
"""

from __future__ import annotations

import time

from secureflow.config import Config
from secureflow.enrichment.cache import EnrichmentCache
from secureflow.enrichment.mitre_mapper import enrich_mitre
from secureflow.enrichment.nvd_client import NvdClient
from secureflow.enrichment.osv_client import OsvClient
from secureflow.utils.logging import get_logger

log = get_logger("agent.enrichment")


def enrich_findings(state: dict) -> dict:
    cfg = Config.model_validate(state.get("config") or {})
    findings = list(state.get("mapped_findings") or [])

    if not findings:
        return {"mapped_findings": []}

    enabled = cfg.enrichment
    cache = EnrichmentCache(
        ttl_seconds=enabled.cache_ttl_hours * 3600,
        enabled=True,
    )
    osv = OsvClient(cache=cache, enabled=enabled.osv)
    nvd = NvdClient(cache=cache, enabled=enabled.nvd)

    deadline = time.monotonic() + max(5, enabled.max_seconds)
    enriched: list[dict] = []
    cves_enriched = 0
    cves_attempted = 0
    deadline_hit = False

    for f in findings:
        out = dict(f)

        if deadline_hit or cves_enriched >= enabled.max_cves_to_enrich:
            # Even when skipping API enrichment, MITRE expansion (local,
            # no network) is still applied below.
            if enabled.mitre:
                out = enrich_mitre(out)
            enriched.append(out)
            continue

        # Order matters here. OSV first because:
        #   - it accepts both CVE-X and GHSA-X identifiers,
        #   - it returns aliases (often adding a CVE-X to a GHSA-X finding),
        #   - it also returns CWE associations from GHSA which the scanner
        #     may not have included.
        # NVD (when enabled) gets a chance to enrich the newly-revealed
        # CVE alias even when the scanner only had a GHSA ID.
        if enabled.osv:
            for ident in list(out.get("cve") or []):
                if time.monotonic() > deadline:
                    deadline_hit = True
                    break
                osv_data = osv.lookup_id(ident)
                if osv_data:
                    _merge_osv(out, osv_data)

        if enabled.nvd and not deadline_hit:
            for ident in list(out.get("cve") or []):
                if time.monotonic() > deadline:
                    deadline_hit = True
                    break
                if not ident.startswith("CVE-"):
                    continue
                cves_attempted += 1
                nvd_data = nvd.lookup_cve(ident)
                if nvd_data:
                    _merge_nvd(out, nvd_data)
                    cves_enriched += 1
                    # One NVD lookup per finding is enough — multiple CVE
                    # aliases for the same advisory return overlapping data.
                    break

        # MITRE expansion runs LAST so it sees CWEs added by OSV/NVD.
        if enabled.mitre:
            out = enrich_mitre(out)

        enriched.append(out)

    log.info(
        "enrichment complete",
        extra={
            "findings": len(enriched),
            "cves_attempted": cves_attempted,
            "cves_enriched": cves_enriched,
            "deadline_hit": deadline_hit,
        },
    )
    update: dict = {"mapped_findings": enriched}
    if deadline_hit:
        update["scanner_errors"] = {
            "enrichment": (
                f"deadline_hit after {enabled.max_seconds}s; "
                f"remaining CVEs not enriched (set NVD_API_KEY for higher rate limit)"
            )
        }
    return update


def _merge_nvd(finding: dict, nvd_data: dict) -> None:
    """Fold NVD details into a finding without overwriting existing data."""
    # Append CVSS score / vector if we have one.
    if nvd_data.get("cvss_score") is not None and "cvss_score" not in finding:
        finding["cvss_score"] = nvd_data["cvss_score"]
        finding["cvss_vector"] = nvd_data.get("cvss_vector")
    # Extra CWEs the scanner may have missed.
    nvd_cwes = nvd_data.get("cwes") or []
    if nvd_cwes:
        existing = list(finding.get("cwe") or [])
        for c in nvd_cwes:
            if c not in existing:
                existing.append(c)
        finding["cwe"] = existing
    # Prefer NVD's curated description over scanner-supplied marketing copy
    # only when the scanner's description is short or generic.
    desc = finding.get("description") or ""
    nvd_desc = nvd_data.get("description") or ""
    if nvd_desc and len(nvd_desc) > len(desc):
        finding["description"] = nvd_desc
    # References — append, capped.
    refs = list(finding.get("references") or [])
    for r in nvd_data.get("references") or []:
        if r not in refs and len(refs) < 8:
            refs.append(r)
    finding["references"] = refs


def _merge_osv(finding: dict, osv_data: dict) -> None:
    """Fold OSV details into a finding."""
    from secureflow.enrichment.cvss import base_score

    aliases = osv_data.get("aliases") or []
    if aliases:
        cves = list(finding.get("cve") or [])
        for a in aliases:
            if isinstance(a, str) and (a.startswith("CVE-") or a.startswith("GHSA-")):
                if a not in cves:
                    cves.append(a)
        finding["cve"] = cves

    # GitHub Advisory Database records (mirrored by OSV) often carry
    # `database_specific.cwe_ids`. Pull them through so downstream MITRE
    # ATT&CK enrichment has something to work with even when scanners
    # didn't ship CWEs.
    db_specific = osv_data.get("database_specific") or {}
    osv_cwes = db_specific.get("cwe_ids") or []
    if osv_cwes:
        existing_cwes = list(finding.get("cwe") or [])
        for c in osv_cwes:
            if isinstance(c, str) and c not in existing_cwes:
                existing_cwes.append(c)
        finding["cwe"] = existing_cwes

    # CVSS: OSV ships V3 vectors under severity[].score. Pull the highest
    # base score we can compute, and keep the vector string for reference.
    if finding.get("cvss_score") is None:
        for sev in osv_data.get("severity") or []:
            if not isinstance(sev, dict):
                continue
            kind = sev.get("type") or ""
            vector = sev.get("score") or ""
            if not vector.startswith("CVSS:3"):
                continue
            score = base_score(vector)
            if score is not None:
                finding["cvss_score"] = score
                finding["cvss_vector"] = vector
                break
            elif "V3" in kind:
                # Record the vector even if score parse failed.
                finding["cvss_vector"] = vector

    refs = list(finding.get("references") or [])
    for r in osv_data.get("references") or []:
        url = r.get("url") if isinstance(r, dict) else None
        if url and url not in refs and len(refs) < 8:
            refs.append(url)
    finding["references"] = refs
