"""Mock app file simulating a PR that adds a file-upload endpoint.

Threat-model intent: new `/upload` route accepts arbitrary file content
and writes it to local disk under a user-controlled name. No size cap,
no MIME validation, no path-traversal check, no auth. SAST may flag the
path-traversal pattern; the threat model agent should additionally
flag this as `new_file_upload` introducing a new trust boundary +
tampering / DoS / elevation-of-privilege risks.
"""

import os
from flask import Flask, request

app = Flask(__name__)

UPLOAD_DIR = "/tmp/uploads"


# NEW IN THIS PR — file-upload endpoint with multiple design flaws.
@app.route("/upload", methods=["POST"])
def upload():
    # User-controlled filename joined to disk path → classic path traversal.
    name = request.form.get("filename") or "default.bin"
    target = os.path.join(UPLOAD_DIR, name)

    # No size cap → trivially DoS-able.
    data = request.get_data()

    # No MIME / extension validation.
    with open(target, "wb") as f:
        f.write(data)
    return {"saved": target}
