# Vulnerable: outbound HTTP with verify=False disables TLS certificate
# validation entirely. MITM-trivial. CWE-295 (improper certificate
# validation).

import requests


def fetch_user(user_id: str) -> dict:
    # In an internal-only context this might be intentional, but the
    # default scanner posture is to flag it loud and let exploitability
    # reasoning judge whether it's actually exploitable here.
    resp = requests.get(
        f"https://internal-svc.example.com/users/{user_id}",
        verify=False,
        timeout=5,
    )
    return resp.json()
