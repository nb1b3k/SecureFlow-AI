# Vulnerable: subprocess with shell=True + user-controlled input.
# CWE-78 (OS command injection); semgrep python.lang.security catches this.

import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    target = request.args.get("host")
    # Concatenating user input into a shell command is the canonical
    # command-injection pattern. shell=True means the OS shell parses it.
    return subprocess.check_output(f"ping -c 1 {target}", shell=True)
