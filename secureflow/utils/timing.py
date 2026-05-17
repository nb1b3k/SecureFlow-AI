"""Timing decorators and context managers for the orchestrator.

Every LangGraph node should be wrapped with `@timed_node("node_name")` so
the entry/exit logs appear with millisecond timing. This makes "where is
the pipeline stuck?" answerable from the logs alone.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from secureflow.utils.logging import get_logger

_log = get_logger("timing")


def timed_node(name: str) -> Callable[[Callable[..., dict]], Callable[..., dict]]:
    """Wrap a LangGraph node function so its execution is timed and logged.

    Logs:
    - INFO on entry: `node {name} start`
    - INFO on exit: `node {name} done` with `duration_ms` and a summary of
      partial-state keys returned.
    - WARNING on exception: `node {name} error` with `duration_ms` and the
      exception class. The exception then re-raises so the orchestrator can
      treat it as terminal or per-node-recoverable per its own rules.
    """

    def decorator(fn: Callable[..., dict]) -> Callable[..., dict]:
        @functools.wraps(fn)
        def wrapper(state: dict, *args: Any, **kwargs: Any) -> dict:
            logger = get_logger(f"node.{name}")
            start = time.monotonic()
            logger.info("node %s start", name, extra={"node": name, "phase": "start"})
            try:
                result = fn(state, *args, **kwargs)
            except Exception as exc:
                duration_ms = int((time.monotonic() - start) * 1000)
                logger.warning(
                    "node %s error: %s",
                    name,
                    type(exc).__name__,
                    extra={
                        "node": name,
                        "phase": "error",
                        "duration_ms": duration_ms,
                        "exc_type": type(exc).__name__,
                    },
                )
                raise
            duration_ms = int((time.monotonic() - start) * 1000)
            keys = sorted((result or {}).keys())
            logger.info(
                "node %s done in %dms",
                name,
                duration_ms,
                extra={
                    "node": name,
                    "phase": "done",
                    "duration_ms": duration_ms,
                    "writes": keys,
                },
            )
            # Record duration onto state for the telemetry artifact. The
            # node_timings field has a dict-merge reducer (state.py), so each
            # node contributes its own key without clobbering siblings.
            if result is None:
                result = {}
            elif not isinstance(result, dict):
                return result
            existing = result.get("node_timings") or {}
            result["node_timings"] = {**existing, name: duration_ms}
            return result

        return wrapper

    return decorator


@contextmanager
def timed_block(name: str, **fields: Any) -> Iterator[None]:
    """Context manager equivalent of `timed_node` for ad-hoc blocks.

    Example:
        with timed_block("semgrep_subprocess", file_count=len(files)):
            run_semgrep(...)
    """
    logger = get_logger(f"block.{name}")
    start = time.monotonic()
    logger.debug("block %s start", name, extra={"block": name, "phase": "start", **fields})
    try:
        yield
    finally:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.debug(
            "block %s done in %dms",
            name,
            duration_ms,
            extra={"block": name, "phase": "done", "duration_ms": duration_ms, **fields},
        )
