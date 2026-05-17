# Intentionally vulnerable fixture: classic string-concatenation SQL injection.
# Semgrep's auto config should flag this; the LLM exploitability step should
# rate it high.

import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB = sqlite3.connect(":memory:")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    # Direct concatenation of user input into SQL is the canonical
    # CWE-89 / OWASP A03 case.
    query = "SELECT * FROM users WHERE id = " + user_id
    cur = DB.cursor()
    cur.execute(query)
    return {"row": cur.fetchone()}
