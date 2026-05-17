"""Minimal SARIF v2.1.0 report writer.

Just enough to be ingestable by `actions/upload-sarif` and shown in
GitHub's "Security" tab. Tool metadata is per-source; if we mix scanners
into one SARIF run, GitHub still renders it sensibly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from secureflow import __version__

_SEV_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_sarif(state: dict) -> dict[str, Any]:
    findings = state.get("final_findings") or state.get("mapped_findings") or []
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = (
            f.get("rule_id")
            or f"{f.get('source','manual')}/{(f.get('title') or 'finding').lower()[:48]}"
        )
        rule_id = rule_id.replace(" ", "_")
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": f.get("title") or rule_id,
                "shortDescription": {"text": f.get("title") or rule_id},
                "fullDescription": {"text": f.get("description") or ""},
                "helpUri": _help_uri(f),
                "properties": {
                    "tags": (f.get("cwe") or []) + (f.get("owasp") or []),
                },
            }

        location: dict = {"physicalLocation": {"artifactLocation": {"uri": f.get("file_path") or ""}}}
        if f.get("start_line"):
            location["physicalLocation"]["region"] = {
                "startLine": f["start_line"],
                "endLine": f.get("end_line") or f["start_line"],
            }

        results.append({
            "ruleId": rule_id,
            "level": _SEV_TO_SARIF_LEVEL.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("description") or f.get("title") or ""},
            "locations": [location],
            "properties": {
                "confidence": f.get("confidence"),
                "source": f.get("source"),
                "reachability": f.get("reachability"),
                "exploitability": f.get("exploitability"),
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureFlow AI",
                        "version": __version__,
                        "informationUri": "https://example.com/secureflow-ai",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(state: dict, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(build_sarif(state), f, ensure_ascii=False, indent=2)
    return p


_CWE_ID_RE = re.compile(r"^CWE-(\d+)")


def _help_uri(f: dict) -> str:
    cves = f.get("cve") or []
    if cves:
        return f"https://nvd.nist.gov/vuln/detail/{cves[0]}"
    cwes = f.get("cwe") or []
    if cwes:
        # Stored values can be `CWE-79` or `CWE-79: Improper Neutralization ...`.
        # SARIF helpUri must be a valid URI — extract just the numeric id.
        m = _CWE_ID_RE.match(cwes[0])
        if m:
            return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
    return "https://owasp.org/www-project-top-ten/"
