# Vulnerable: open(user_supplied_path) with no containment check.
# CWE-22 (path traversal). An attacker can request '../../etc/passwd'.

import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOADS_DIR = "/var/app/uploads"


@app.route("/download")
def download():
    filename = request.args.get("name")
    # Joining with a "safe" root doesn't help — `..` segments traverse.
    # The fix is to resolve+normalize and assert the result is inside
    # UPLOADS_DIR.
    path = os.path.join(UPLOADS_DIR, filename)
    return send_file(path)
