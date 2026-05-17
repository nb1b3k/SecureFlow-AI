# Intentionally vulnerable fixture: a Flask admin endpoint with no authorization check.
# Traditional SAST scanners typically miss this — it's a missing-control problem,
# not a pattern problem. The AI Discovery agent should flag it (OWASP A01).

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_all_users() -> list[dict]:
    """Pretend to load every user row from the database."""
    return [{"id": 1, "email": "alice@example.com"}, {"id": 2, "email": "bob@example.com"}]


@app.route("/admin/users")
def list_users():
    # No authentication check. No authorization check. Anyone with the URL
    # can list every user record. Classic OWASP A01 / CWE-862.
    return jsonify(get_all_users())


@app.route("/admin/delete-user", methods=["POST"])
def delete_user():
    # Same problem, but worse — this also lets anyone delete users.
    user_id = request.json.get("id")
    return jsonify({"deleted": user_id})
