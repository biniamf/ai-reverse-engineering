# Biniam Demissie
"""Application logging configuration."""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from typing import Any

_HANDLER_TAG = "_ghidra_webui_handler"

# Patterns scrubbed from every emitted message. Case-insensitive. Each captures
# a leading key/label so we only redact the sensitive value, not the whole line.
_REDACTIONS = (
    # Authorization: Bearer <token> -- redact the whole value to end of line.
    (re.compile(r"(authorization\s*[:=]\s*).+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(bearer\s+)([A-Za-z0-9._\-]+)", re.I), r"\1[REDACTED]"),
    # api_key=..., api-key: ..., "api_key": "..."
    (re.compile(r"(api[_-]?key\"?\s*[:=]\s*\"?)([^\s\"',}]+)", re.I), r"\1[REDACTED]"),
    (re.compile(r"(x-api-key\s*[:=]\s*)(\S+)", re.I), r"\1[REDACTED]"),
    (re.compile(r"(sk-)[A-Za-z0-9]{8,}", re.I), r"\1[REDACTED]"),
    (re.compile(r"(file_b64\"?\s*[:=]\s*\"?)([^\s\"',}]+)", re.I), r"\1[REDACTED]"),
)


def redact(text: str) -> str:
    """Scrub secrets/large blobs from a log string. Pure and testable."""
    if not text:
        return text
    out = text
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    return out


class RedactionFilter(logging.Filter):
    """Apply :func:`redact` to the formatted message of every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


class _RequestContextFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = []
        for key in ("request_id", "job_id", "method", "path", "status", "duration_ms"):
            value = getattr(record, key, None)
            if value not in (None, ""):
                extras.append(f"{key}={value}")
        if extras:
            base = f"{base} [{' '.join(extras)}]"
        return redact(base)


def configure_logging(config: Any) -> None:
    """Configure the root logger from ``config``. Idempotent."""
    level_name = str(getattr(config, "log_level", "INFO") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    for handler in list(root.handlers):
        if getattr(handler, _HANDLER_TAG, False):
            root.removeHandler(handler)

    formatter = _RequestContextFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    redaction = RedactionFilter()

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    stream.addFilter(redaction)
    setattr(stream, _HANDLER_TAG, True)
    root.addHandler(stream)

    log_file = getattr(config, "log_file", None)
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=int(getattr(config, "log_max_bytes", 5 * 1024 * 1024)),
            backupCount=int(getattr(config, "log_backup_count", 3)),
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction)
        setattr(file_handler, _HANDLER_TAG, True)
        root.addHandler(file_handler)
