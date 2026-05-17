"""Combined-PR fixture: app code with multiple distinct vulnerabilities.

Exercises the orchestrator's fan-out + normalizer's dedup + cross-stream
finding handling. Should produce findings from at least:
  - semgrep (SQL injection on line 19, weak hash on line 27)
  - gitleaks (hardcoded API key on line 12)

Combined with the Dockerfile and main.tf in the same fixture directory,
this validates that secrets_scan + sast_scan + iac_scan all fire in
parallel on a single scan target.
"""

from __future__ import annotations

import hashlib
import sqlite3

# Hardcoded secret — gitleaks should flag.
STRIPE_API_KEY = "sk_live_51HsT1Lj9zKw3eXxY7BvNqRm8FpGdJaY2hUcTvWxYsR6kPnLpQwErTyUiOpAsDfGhJkL"


def get_user(uid: str) -> dict:
    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    # SQL injection — semgrep should flag.
    cur.execute("SELECT * FROM users WHERE id = '" + uid + "'")
    row = cur.fetchone()
    return {"id": row[0], "name": row[1]} if row else {}


def hash_password(pw: str) -> str:
    # Weak crypto — semgrep should flag.
    return hashlib.md5(pw.encode()).hexdigest()
