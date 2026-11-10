"""Structured logging with automatic PII redaction and correlation IDs."""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

request_id_ctx_var: ContextVar[str] = ContextVar("request_id", default="-")

# Regex patterns to scrub accidental phone numbers, bearer tokens, passwords/keys, or BVN/NIN in logs
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\d)(\+?234\d{10}|0[789][01]\d{8})(?!\d)")
_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|password|passwd|secret|access[_-]?token)\s*[:=]\s*([^\s,;&'\"]+)"
)


def redact_sensitive_text(message: str) -> str:
    """Redact sensitive credentials, Nigerian phone numbers, and Bearer tokens from log messages."""
    redacted = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", message)
    redacted = _KEY_VALUE_SECRET_RE.sub(r"\1=[REDACTED_CREDENTIAL]", redacted)
    redacted = _PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    return redacted


class StructuredJsonFormatter(logging.Formatter):
    """Format log records as single-line JSON objects without exposing raw user PII."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "request_id": request_id_ctx_var.get("-"),
            "message": redact_sensitive_text(record.getMessage()),
        }
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            for key, value in record.extra_fields.items():
                if key.lower() in {"raw_text", "password", "secret", "token", "authorization"}:
                    payload[key] = "[REDACTED]"
                else:
                    payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(log_level: str = "INFO") -> None:
    """Configure root and application loggers with structured JSON output."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())

    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Silence overly verbose third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
