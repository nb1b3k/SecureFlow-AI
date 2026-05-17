"""MITRE ATT&CK expansion via CWE → technique mapping.

Source: MITRE's published CWE / CAPEC / ATT&CK linkages (Center for
Threat-Informed Defense). We curate a static subset here rather than
fetching the full STIX bundle at scan time — it would add a heavy
dependency and the mappings rarely change between MITRE releases.

Use `enrich_mitre(finding)` to mutate a finding's `mitre_attack` list to
include any techniques whose CWE associations cover the finding's CWEs.

Refresh the table by re-reading the upstream mappings; document the
source in any pull request that updates this file.
"""

from __future__ import annotations

from secureflow.utils.logging import get_logger

log = get_logger("enrich.mitre")

# CWE → list[ATT&CK technique ID]. Curated subset relevant to web/code-review
# findings. ATT&CK IDs follow `TXXXX` (with optional `.NNN` sub-technique).
_CWE_TO_ATTACK: dict[str, list[str]] = {
    # Credential / secret exposure
    "CWE-798": ["T1552.001"],   # Credentials in files
    "CWE-321": ["T1552.001"],   # Hardcoded crypto key
    "CWE-259": ["T1552.001"],   # Hardcoded password
    "CWE-256": ["T1552.001"],   # Unprotected storage of credentials
    # Injection
    "CWE-89":  ["T1190"],       # SQL injection → exploit public app
    "CWE-78":  ["T1059"],       # OS command injection → command/script
    "CWE-77":  ["T1059"],       # Generic command injection
    "CWE-94":  ["T1059"],       # Code injection
    "CWE-95":  ["T1059"],       # Eval-style injection
    "CWE-917": ["T1059"],       # Expression-language injection
    "CWE-643": ["T1190"],       # XPath injection
    "CWE-91":  ["T1190"],       # XML injection
    "CWE-79":  ["T1059.007"],   # XSS → JavaScript execution
    "CWE-352": ["T1185"],       # CSRF → browser session hijack
    # SSRF / file disclosure
    "CWE-918": ["T1090"],       # SSRF → proxy/internal pivot
    "CWE-22":  ["T1083"],       # Path traversal → discovery / file
    "CWE-23":  ["T1083"],
    "CWE-36":  ["T1083"],
    # Deserialization / unsafe data
    "CWE-502": ["T1190"],       # Insecure deserialization
    # Access control / authz
    "CWE-862": ["T1078"],       # Missing authorization → valid accounts
    "CWE-863": ["T1078"],       # Incorrect authorization
    "CWE-639": ["T1078"],       # IDOR
    "CWE-285": ["T1078"],       # Improper authorization
    "CWE-284": ["T1078"],       # Improper access control
    # Authentication
    "CWE-287": ["T1078"],       # Improper authentication
    "CWE-306": ["T1078"],       # Missing authentication for critical fn
    # Crypto / data integrity
    "CWE-327": ["T1573"],       # Weak crypto → encrypted channel abuse
    "CWE-328": ["T1573"],       # Weak hash
    "CWE-330": ["T1573"],       # Insufficient randomness
    "CWE-347": ["T1078"],       # Improper signature verification
    # Sensitive data exposure / logging
    "CWE-532": ["T1552"],       # Insertion of sensitive info into logs
    "CWE-200": ["T1213"],       # Exposure of sensitive info
    "CWE-209": ["T1213"],       # Verbose error → information leak
    # Open redirect / impersonation
    "CWE-601": ["T1566"],       # Open redirect → phishing
    # XXE
    "CWE-611": ["T1190"],       # XML external entity
    # Race / TOCTOU
    "CWE-367": ["T1068"],       # TOCTOU → priv escalation
    # File upload
    "CWE-434": ["T1190"],       # Unrestricted file upload
}


def enrich_mitre(finding: dict) -> dict:
    """Add ATT&CK techniques implied by the finding's CWEs."""
    cwes = [c for c in (finding.get("cwe") or []) if isinstance(c, str)]
    if not cwes:
        return finding
    existing = list(finding.get("mitre_attack") or [])
    added = 0
    for cwe in cwes:
        # Some scanners report `CWE-89: SQL injection` style; take the first
        # whitespace/colon-delimited token.
        head = cwe.split(":")[0].split()[0].strip()
        for technique in _CWE_TO_ATTACK.get(head, []):
            if technique not in existing:
                existing.append(technique)
                added += 1
    if added:
        log.debug(
            "mitre expanded",
            extra={
                "finding_id": finding.get("id"),
                "added": added,
                "cwes": cwes,
            },
        )
    finding["mitre_attack"] = existing
    return finding
