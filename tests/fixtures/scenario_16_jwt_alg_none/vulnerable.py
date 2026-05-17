# Vulnerable: decoding a JWT without verifying the signature. CWE-345
# (insufficient verification of authenticity) + CWE-327 (broken crypto).
# An attacker mints any payload they want and the server trusts it.

import jwt
from flask import Flask, request

app = Flask(__name__)
JWT_SECRET = "secret-from-config"


@app.route("/admin")
def admin():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    # verify_signature=False disables the entire authenticity check; the
    # token's `alg: none` would also be accepted with this configuration.
    payload = jwt.decode(token, options={"verify_signature": False})
    return {"hello": payload.get("user", "anon")}
