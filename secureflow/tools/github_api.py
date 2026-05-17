"""GitHub PR commenter — minimal v1 implementation.

Posts (or updates) a single bot comment marked with an HTML comment marker
so re-runs edit the existing comment instead of spamming new ones.

Phase 1 keeps this thin; full PR metadata extraction lives in `context_agent`
when `GITHUB_ACTIONS=true`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from secureflow.utils.logging import get_logger

log = get_logger("github")

MARKER = "<!-- secureflow-ai:bot-comment -->"


def _api(token: str, method: str, url: str, body: dict | None = None) -> dict | list:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "secureflow-ai")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_or_update_comment(
    *,
    repo: str,
    pr_number: int,
    body: str,
    token: str | None = None,
) -> str | None:
    """Create or update the SecureFlow bot comment on a PR.

    Returns the URL of the comment, or None if no token was available
    (in which case nothing was posted).
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    if not token:
        log.info("no GITHUB_TOKEN; skipping PR comment")
        return None

    marked_body = f"{MARKER}\n{body}"
    list_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    try:
        comments = _api(token, "GET", list_url)
    except urllib.error.HTTPError as e:
        log.warning("github list-comments failed: %s", e)
        return None
    if not isinstance(comments, list):
        comments = []

    existing_id: int | None = None
    for c in comments:
        if isinstance(c, dict) and MARKER in (c.get("body") or ""):
            existing_id = c.get("id")
            break

    try:
        if existing_id is not None:
            r = _api(
                token,
                "PATCH",
                f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}",
                {"body": marked_body},
            )
        else:
            r = _api(token, "POST", list_url, {"body": marked_body})
    except urllib.error.HTTPError as e:
        log.warning("github post-comment failed: %s", e)
        return None
    return r.get("html_url") if isinstance(r, dict) else None
