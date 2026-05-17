# Vulnerable: Flask redirect to a user-supplied URL with no host check.
# CWE-601. An attacker crafts a link that bounces through this endpoint to
# a phishing page hosted on a domain they control.

from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    # No allowlist of hosts, no scheme check, no relative-only enforcement.
    return redirect(target)
