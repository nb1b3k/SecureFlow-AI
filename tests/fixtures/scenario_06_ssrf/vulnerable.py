# Vulnerable: server-side request forgery (SSRF). The URL comes straight
# from the request — an attacker can ask the server to fetch internal
# metadata services (169.254.169.254), file:// URLs, etc.
# CWE-918.

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # No allowlist, no scheme check, no metadata-IP block.
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "body": resp.text[:200]})
