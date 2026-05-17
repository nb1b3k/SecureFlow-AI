# Vulnerable: pickle.loads on attacker-controlled bytes is RCE-equivalent
# (pickle deserialization can call arbitrary code via __reduce__).
# CWE-502.

import base64
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/session", methods=["POST"])
def load_session():
    blob = request.get_data()
    decoded = base64.b64decode(blob)
    # Anything that comes through the request body becomes Python code.
    obj = pickle.loads(decoded)
    return {"loaded": True, "type": type(obj).__name__}
