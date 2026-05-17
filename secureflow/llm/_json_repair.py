"""Tolerant JSON parser used as a fallback by every LLM client.

LLMs occasionally produce *almost*-valid JSON when constrained to a
structured-output schema: a key without quotes, an unterminated string
near `max_tokens`, a missing comma between properties. Pre-prod logs
from the comprehensive eval surfaced four distinct shapes in a single
run on PR #10:

  - `Expecting property name enclosed in double quotes: line 197 col 295`
  - `Unterminated string starting at: line 233 col 16`
  - `Unterminated string starting at: line 102 col 19`
  - `Expecting ',' delimiter: line 44 col 377`

All four are repairable by `json_repair` without re-prompting the model.
Recovering at the client costs nothing extra; re-prompting costs an
LLM call AND latency. Stronger models (e.g. `deepseek-reasoner`) reduce
the error rate but at 2–4× cost — the repair fallback is the better
unit-economics fix.

Usage from each client's `_validate`:

    from secureflow.llm._json_repair import parse_with_repair
    parsed_obj = parse_with_repair(content_str)
    finding = SchemaType.model_validate(parsed_obj)

`parse_with_repair` always returns a Python object or raises a final
`json.JSONDecodeError` that we surface to the chain's transient-error
classifier so the next provider link can still take over for the rare
unrepairable cases.
"""

from __future__ import annotations

import json
from typing import Any

from secureflow.utils.logging import get_logger

log = get_logger("llm.json_repair")


def parse_with_repair(content: str) -> Any:
    """Parse `content` as JSON, with a `json_repair` fallback on failure.

    The fast path is plain `json.loads` — succeeds on the >95% of
    responses that are clean and avoids the repair-library import + work.
    Only when strict parse fails do we invoke `json_repair.repair_json`.
    """
    cleaned = _strip_markdown_fences(content)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as first_err:
        # Lazy import — only pay the cost when we actually need to repair.
        try:
            from json_repair import repair_json
        except ImportError:
            # json-repair is a hard dep in pyproject.toml; if missing,
            # we're in a busted install. Re-raise the original error so
            # the LLM client's retry/failover logic kicks in.
            log.warning("json_repair not installed; cannot recover from malformed JSON")
            raise first_err
        try:
            repaired = repair_json(cleaned, return_objects=False)
            data = json.loads(repaired)
            log.info(
                "recovered malformed JSON via json_repair",
                extra={"original_error": str(first_err)[:200]},
            )
            return data
        except (json.JSONDecodeError, Exception) as repair_err:  # noqa: BLE001
            # Bubble the ORIGINAL error up — it's more useful for the
            # caller's retry-prompt than the repair library's message.
            log.warning(
                "json_repair could not recover content (first err: %s ; repair err: %s)",
                str(first_err)[:200], str(repair_err)[:200],
            )
            raise first_err


def _strip_markdown_fences(content: str) -> str:
    """Remove ```json … ``` fences if the model wrapped its response."""
    s = (content or "").strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s.lower().startswith("json"):
            s = s[4:].lstrip()
        s = s.rstrip("`").strip()
    return s
