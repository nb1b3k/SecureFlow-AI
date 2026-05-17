"""Threat mapping — CWE / OWASP / MITRE ATT&CK.

Deterministic table first. The plan's rule (§8.7) "don't force ATT&CK onto
every finding" is enforced: ATT&CK is only added for findings whose pattern
clearly maps to an adversary technique. The LLM fallback for unmapped
findings is reserved for a later phase.
"""

from __future__ import annotations

from collections.abc import Iterable

from secureflow.utils.logging import get_logger

log = get_logger("agent.threat_map")

# Rule-keyword → (CWE list, OWASP list, ATT&CK list)
_PATTERN_TABLE: tuple[tuple[tuple[str, ...], list[str], list[str], list[str]], ...] = (
    (("sql-injection", "sqli"),
     ["CWE-89"], ["A03:2021-Injection"], []),
    (("command-injection", "shell-injection", "os-command"),
     ["CWE-78"], ["A03:2021-Injection"], ["T1059"]),
    (("ssrf",),
     ["CWE-918"], ["A10:2021-Server-Side Request Forgery"], []),
    (("deserialization", "pickle", "yaml.load", "unsafe-yaml"),
     ["CWE-502"], ["A08:2021-Software and Data Integrity Failures"], []),
    (("xss",),
     ["CWE-79"], ["A03:2021-Injection"], []),
    (("path-traversal", "directory-traversal"),
     ["CWE-22"], ["A01:2021-Broken Access Control"], []),
    (("open-redirect",),
     ["CWE-601"], [], []),
    (("missing-authorization", "missing-authz", "broken-access-control"),
     ["CWE-862"], ["A01:2021-Broken Access Control"], []),
    (("weak-cryptography", "md5", "sha1", "des"),
     ["CWE-327"], ["A02:2021-Cryptographic Failures"], []),
    (("hardcoded", "secret", "credential"),
     ["CWE-798"], ["A07:2021-Identification and Authentication Failures"], ["T1552.001"]),
    (("idor", "insecure-direct-object"),
     ["CWE-639"], ["A01:2021-Broken Access Control"], []),
)


def _merge_unique(existing: Iterable[str], new: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for v in list(existing) + list(new):
        if v and v not in seen:
            seen.append(v)
    return seen


def _enrich(finding: dict) -> dict:
    text = f"{finding.get('rule_id') or ''} {finding.get('title') or ''}".lower()
    cwe = list(finding.get("cwe") or [])
    owasp = list(finding.get("owasp") or [])
    attack = list(finding.get("mitre_attack") or [])

    for keywords, cwes, owasps, attacks in _PATTERN_TABLE:
        if any(k in text for k in keywords):
            cwe = _merge_unique(cwe, cwes)
            owasp = _merge_unique(owasp, owasps)
            attack = _merge_unique(attack, attacks)

    finding["cwe"] = cwe
    finding["owasp"] = owasp
    finding["mitre_attack"] = attack
    return finding


def threat_map(state: dict) -> dict:
    findings = list(state.get("normalized_findings") or [])
    enriched = [_enrich(dict(f)) for f in findings]
    log.info("threat map applied to %d findings", len(enriched))
    return {"mapped_findings": enriched}
