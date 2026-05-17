"""Safe Python fixture — true negative.

A small, deliberately-secure piece of code: parameterised SQL, no
secrets, no weak crypto, no dangerous imports. The pipeline should
produce no blocking findings and reach PASS.

Validates the false-positive rate floor: a clean PR must NOT FAIL.
"""

from __future__ import annotations

import os
import sqlite3


def get_user(db_path: str, uid: int) -> dict | None:
    """Parameterised query — no string concatenation, no shell."""
    with sqlite3.connect(db_path) as db:
        cur = db.cursor()
        cur.execute("SELECT id, name FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
    return {"id": row[0], "name": row[1]} if row else None


def load_config() -> dict:
    """Read settings from env, not hardcoded literals."""
    return {
        "api_endpoint": os.environ["API_ENDPOINT"],
        "timeout_seconds": int(os.environ.get("TIMEOUT_SECONDS", "30")),
    }
