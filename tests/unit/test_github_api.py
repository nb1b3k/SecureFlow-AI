"""Unit tests for the GitHub PR-comment helper.

We monkey-patch `urllib.request.urlopen` so the tests run offline and
deterministically. Each test asserts both the visible behavior (created
vs updated vs skipped) and the HTTP plumbing (right URL, right method).
"""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Callable
from unittest.mock import patch

from secureflow.tools.github_api import MARKER, post_or_update_comment

# ──────────────────────────────────────────────────────────── helpers ──


class _FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc) -> None:
        return None


def _fake_urlopen(responder: Callable[[object], _FakeResponse]) -> Callable:
    """Build a urlopen replacement that delegates to `responder(req)`."""

    captured: list[dict] = []

    def _opener(req, timeout=None):
        captured.append({
            "url": req.full_url,
            "method": req.get_method(),
            "data": req.data.decode("utf-8") if req.data else None,
            "headers": dict(req.header_items()),
        })
        return responder(req)

    _opener.captured = captured  # type: ignore[attr-defined]
    return _opener


# ──────────────────────────────────────────────────────────── tests ──


def test_returns_none_when_no_token(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    result = post_or_update_comment(repo="owner/repo", pr_number=42, body="hi")
    assert result is None


def test_creates_comment_when_no_prior_bot_comment() -> None:
    """GET returns an empty comments list → POST a new comment."""

    def responder(req):
        method = req.get_method()
        if method == "GET":
            return _FakeResponse([])  # no existing comments
        if method == "POST":
            return _FakeResponse({"html_url": "https://github.com/owner/repo/issues/42#issuecomment-1"})
        raise AssertionError(f"unexpected method {method}")

    opener = _fake_urlopen(responder)
    with patch("urllib.request.urlopen", opener):
        url = post_or_update_comment(
            repo="owner/repo", pr_number=42, body="**hi**", token="t",
        )
    assert url == "https://github.com/owner/repo/issues/42#issuecomment-1"
    requests = opener.captured  # type: ignore[attr-defined]
    assert len(requests) == 2
    assert requests[0]["method"] == "GET"
    assert "/issues/42/comments" in requests[0]["url"]
    assert requests[1]["method"] == "POST"
    # The body MUST include our marker so future runs can find this comment.
    assert MARKER in json.loads(requests[1]["data"])["body"]


def test_updates_existing_bot_comment() -> None:
    """GET returns a comment containing the marker → PATCH it, don't POST."""
    existing_id = 99

    def responder(req):
        method = req.get_method()
        url = req.full_url
        if method == "GET":
            return _FakeResponse([
                {"id": 7, "body": "unrelated user comment"},
                {"id": existing_id, "body": f"{MARKER}\nprior body"},
            ])
        if method == "PATCH":
            assert f"/issues/comments/{existing_id}" in url
            return _FakeResponse({"html_url": "https://github.com/owner/repo/issues/42#updated"})
        raise AssertionError(f"unexpected method {method}")

    opener = _fake_urlopen(responder)
    with patch("urllib.request.urlopen", opener):
        url = post_or_update_comment(
            repo="owner/repo", pr_number=42, body="updated body", token="t",
        )
    assert url == "https://github.com/owner/repo/issues/42#updated"
    requests = opener.captured  # type: ignore[attr-defined]
    methods = [r["method"] for r in requests]
    assert methods == ["GET", "PATCH"]
    assert "POST" not in methods


def test_silent_skip_on_list_http_error() -> None:
    """List comments failed (e.g. 403) → return None, don't POST."""

    def responder(req):
        raise urllib.error.HTTPError(
            req.full_url, 403, "forbidden", hdrs=None, fp=io.BytesIO(b""),
        )

    opener = _fake_urlopen(responder)
    with patch("urllib.request.urlopen", opener):
        url = post_or_update_comment(
            repo="owner/repo", pr_number=42, body="hi", token="t",
        )
    assert url is None


def test_post_failure_returns_none() -> None:
    """GET succeeds but POST fails → return None, no crash."""

    def responder(req):
        if req.get_method() == "GET":
            return _FakeResponse([])
        raise urllib.error.HTTPError(
            req.full_url, 500, "server error", hdrs=None, fp=io.BytesIO(b""),
        )

    opener = _fake_urlopen(responder)
    with patch("urllib.request.urlopen", opener):
        url = post_or_update_comment(
            repo="owner/repo", pr_number=42, body="hi", token="t",
        )
    assert url is None


def test_authorization_header_uses_bearer() -> None:
    """We send `Authorization: Bearer <token>` per GitHub's modern API."""

    def responder(req):
        if req.get_method() == "GET":
            return _FakeResponse([])
        return _FakeResponse({"html_url": "x"})

    opener = _fake_urlopen(responder)
    with patch("urllib.request.urlopen", opener):
        post_or_update_comment(
            repo="owner/repo", pr_number=42, body="hi", token="secret-token-XYZ",
        )
    headers_seen = opener.captured[0]["headers"]  # type: ignore[attr-defined]
    # urllib normalises header names with first-letter-cap.
    auth = headers_seen.get("Authorization", "")
    assert auth.startswith("Bearer ")
    # Token value should be in the header (we're not asserting masking
    # here — that's the caller's job; we just verify it's transmitted).
    assert "secret-token-XYZ" in auth
