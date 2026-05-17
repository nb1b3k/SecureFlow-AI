"""Unit tests for sensitive-file detection (design/06 §1)."""

from __future__ import annotations

from secureflow.analysis.ast_signals import detect


def test_flask_route_is_sensitive() -> None:
    content = """\
from flask import Flask
app = Flask(__name__)

@app.route('/admin')
def admin():
    return 'ok'
"""
    res = detect(file_path="core.py", content=content)
    assert res.sensitive
    assert "route_decorator" in res.signals


def test_auth_import_is_sensitive() -> None:
    content = "from passlib.hash import bcrypt\n"
    res = detect(file_path="security.py", content=content)
    assert res.sensitive
    assert "auth_import" in res.signals


def test_iam_policy_is_sensitive() -> None:
    content = '{"Effect": "Allow", "Action": "*"}'
    res = detect(file_path="policy.json", content=content)
    assert res.sensitive
    assert "iam_policy" in res.signals


def test_test_file_with_auth_keyword_is_not_sensitive() -> None:
    content = "# just a test\nassert True"
    res = detect(
        file_path="tests/test_auth.py",
        content=content,
        sensitive_path_patterns=["auth"],
        exclusion_paths=["tests/"],
    )
    assert not res.sensitive


def test_real_route_in_tests_overrides_exclusion() -> None:
    content = "@app.route('/admin')\ndef admin(): return 'x'"
    res = detect(
        file_path="tests/conftest.py",
        content=content,
        exclusion_paths=["tests/"],
    )
    # AST signal beats the exclusion list.
    assert res.sensitive


def test_innocent_file_is_not_sensitive() -> None:
    res = detect(file_path="src/math/calculator.py", content="def add(a, b): return a + b\n")
    assert not res.sensitive


def test_bare_hashlib_import_is_sensitive() -> None:
    """Plain `import hashlib` should fire crypto_import even without a
    submodule reference — AI Discovery should review hash choices."""
    res = detect(file_path="auth.py", content="import hashlib\n\ndef h(s):\n    return hashlib.md5(s)\n")
    assert res.sensitive
    assert "crypto_import" in res.signals


def test_ssl_verify_false_is_sensitive() -> None:
    content = "import requests\nrequests.get('https://x', verify=False)\n"
    res = detect(file_path="client.py", content=content)
    assert res.sensitive
    # Either signal qualifies but both should fire.
    assert "tls_insecure_config" in res.signals
    assert "network_client_import" in res.signals


def test_outbound_http_client_alone_is_sensitive() -> None:
    """A file that imports requests/httpx is SSRF-adjacent and worth a
    review even without a verify=False or auth concern."""
    res = detect(file_path="fetcher.py", content="import requests\nresp = requests.get(url)\n")
    assert res.sensitive
    assert "network_client_import" in res.signals


def test_embedded_private_key_is_sensitive() -> None:
    content = (
        "# config\n"
        'KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"""\n'
    )
    res = detect(file_path="config.py", content=content)
    assert res.sensitive
    assert "embedded_secret" in res.signals
