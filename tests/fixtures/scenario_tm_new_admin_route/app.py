"""Mock app file simulating a PR that adds an admin endpoint.

Threat-model intent: a new /admin/users/<id> handler is added that returns
arbitrary user records. No @require_admin decorator, no role check, no
audit log. SAST won't flag this — the function is syntactically fine —
but a threat model review should call out "new admin route without
authorization" as a STRIDE elevation-of-privilege risk.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return {"ok": True}


# NEW IN THIS PR — vulnerable admin route.
@app.route("/admin/users/<int:user_id>")
def admin_get_user(user_id: int):
    # Looks up and returns the full user record including PII.
    # No authn / authz check. Any caller (even unauthenticated) can hit this.
    user = _fetch_user_record(user_id)
    return jsonify(user)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id: int):
    # No CSRF protection, no auth check, no audit log.
    _delete_user(user_id)
    return {"deleted": user_id}


def _fetch_user_record(user_id: int) -> dict:
    return {
        "id": user_id,
        "email": "user@example.com",
        "ssn": "xxx-xx-xxxx",
        "card_last4": "1234",
    }


def _delete_user(user_id: int) -> None:
    pass
