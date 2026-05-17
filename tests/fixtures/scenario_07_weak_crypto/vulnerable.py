# Vulnerable: MD5 for password hashing. MD5 is broken for any security
# purpose — collisions are trivial, length-extension attacks apply, and
# there is no salt/key-stretching here.
# CWE-327 (broken/risky cryptography), CWE-916 (missing key-derivation).

import hashlib


def hash_password(password: str) -> str:
    # Semgrep flags md5(...) and sha1(...) for non-cryptographic uses.
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash
