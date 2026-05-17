# Vulnerable: Flask render_template_string with user input concatenation
# produces a Jinja injection / reflected XSS. CWE-79.

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # The template body is constructed with user input. An attacker can
    # supply {{ config }} or other Jinja expressions to read server state.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
