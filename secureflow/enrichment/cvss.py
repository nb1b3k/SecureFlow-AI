"""Local CVSS v3.x base-score calculator.

OSV records frequently include a CVSS V3 vector string under `severity[].score`.
With this calculator we can derive a numeric base score (0.0–10.0) from that
vector — no external API call needed.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math

_AV: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED:   dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA: dict[str, float] = {"N": 0.00, "L": 0.22, "H": 0.56}


def parse_vector(vector: str) -> dict[str, str]:
    """Parse `CVSS:3.x/AV:N/AC:L/.../A:H` → `{"AV":"N","AC":"L",...}`."""
    parts = vector.split("/")
    out: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score for the given vector, or None on error.

    The result is rounded to one decimal place, as the v3.1 specification
    prescribes (`Roundup(...)` ≈ ceil to nearest 0.1).
    """
    try:
        m = parse_vector(vector)
        if not m.get("CVSS", "").startswith("3."):
            return None
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        scope = m["S"]
        pr_table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
        pr = pr_table[m["PR"]]
        ui = _UI[m["UI"]]
        c = _CIA[m["C"]]
        i = _CIA[m["I"]]
        a = _CIA[m["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = min(10.0, impact + exploitability)
    else:
        score = min(10.0, 1.08 * (impact + exploitability))

    # CVSS v3.1 Roundup: smallest multiple of 0.1 that is ≥ score.
    return math.ceil(score * 10) / 10
