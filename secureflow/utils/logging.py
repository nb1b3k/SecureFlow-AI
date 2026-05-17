"""Structured logging.

Two destinations:
- A `rich`-formatted handler for human terminal output.
- A JSON handler for CI capture (one event per line).

All log records pass through `secret_masker` so we never log raw secrets.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

from secureflow.utils.secret_masker import mask

_LOGGER_NAME = "secureflow"
_CONFIGURED = False


class _MaskingFilter(logging.Filter):
    """Apply the secret masker to every log record's rendered message."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = mask(str(record.msg))
            if record.args:
                masked_args: tuple[Any, ...] = tuple(
                    mask(a) if isinstance(a, str) else a for a in record.args
                )
                record.args = masked_args
        except Exception:
            # Never let logging itself raise.
            pass
        return True


class _JsonFormatter(logging.Formatter):
    """One-line JSON per event. CI-friendly."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach extra fields, but only those that JSON-serialize cleanly.
        for key, value in record.__dict__.items():
            if key in {
                "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno",
                "funcName", "created", "msecs", "relativeCreated", "thread",
                "threadName", "processName", "process", "name",
            }:
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except TypeError:
                payload[key] = repr(value)
        return json.dumps(payload, ensure_ascii=False)


def configure(
    level: str = "INFO",
    *,
    json_output: bool | None = None,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure the SecureFlow logger. Safe to call multiple times."""
    global _CONFIGURED

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level.upper())

    if _CONFIGURED:
        return logger

    if json_output is None:
        # Default to JSON on CI runners.
        json_output = os.environ.get("CI", "").lower() == "true" or bool(
            os.environ.get("GITHUB_ACTIONS")
        )

    handler: logging.Handler
    if json_output:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
    else:
        # Lazy import so `rich` isn't required if user wants JSON-only output.
        try:
            from rich.logging import RichHandler

            handler = RichHandler(rich_tracebacks=True, show_path=False)
        except Exception:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )

    handler.addFilter(_MaskingFilter())
    logger.addHandler(handler)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(_JsonFormatter())
        fh.addFilter(_MaskingFilter())
        logger.addHandler(fh)

    logger.propagate = False
    _CONFIGURED = True
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger under the `secureflow.*` namespace."""
    if name is None or name == _LOGGER_NAME:
        return logging.getLogger(_LOGGER_NAME)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")
