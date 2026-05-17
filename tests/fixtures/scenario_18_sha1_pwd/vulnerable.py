# Vulnerable: SHA-1 for password hashing. Variant of weak_crypto; SHA-1
# is collision-broken since 2017 and offers no key-stretching. CWE-327.

import hashlib


def hash_password(password: str) -> str:
    # Semgrep's hashlib.sha1 / weak-hash rules flag this; even in the
    # absence of those, AI Discovery should call it out under cryptography.
    return hashlib.sha1(password.encode("utf-8")).hexdigest()
