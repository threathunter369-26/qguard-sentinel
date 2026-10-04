"""Structured logging with automatic secret redaction.

Security platforms process credentials, tokens and evidence by nature, so the
logger scrubs sensitive keys and token-shaped strings before anything is
emitted. Requests carry a ``request_id`` that is bound into every log line for
the duration of the request and returned in the response headers.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import MutableMapping
from contextvars import ContextVar
from typing import Any

import structlog

from qguard.common.config import get_settings

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
actor_id_var: ContextVar[str | None] = ContextVar("actor_id", default=None)
org_id_var: ContextVar[str | None] = ContextVar("org_id", default=None)

#: Keys whose values are replaced wholesale.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "current_password",
        "new_password",
        "secret",
        "secret_value",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "set-cookie",
        "session",
        "jwt",
        "jwt_secret",
        "private_key",
        "encryption_key",
        "mfa_secret",
        "totp_secret",
        "otp",
        "service_role_key",
        "anon_key",
        "aws_secret_access_key",
        "credentials",
        "signature",
    }
)

REDACTED = "«redacted»"

#: Token-shaped literals that must never appear in logs even in free text.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
    re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b"),  # GitHub
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS key id
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # API keys
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),  # PEM
)


def scrub(value: Any, _depth: int = 0) -> Any:
    """Recursively redact sensitive keys and token-shaped strings."""
    if _depth > 8:
        return value
    if isinstance(value, MutableMapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                out[str(key)] = REDACTED
            else:
                out[str(key)] = scrub(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        return type(value)(scrub(item, _depth + 1) for item in value)
    if isinstance(value, str):
        scrubbed = value
        for pattern in _TOKEN_PATTERNS:
            scrubbed = pattern.sub(REDACTED, scrubbed)
        return scrubbed
    return value


def _redaction_processor(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    scrubbed = scrub(event_dict)
    # ``scrub`` returns the same mapping shape it was given, which for an
    # event dict is a mapping; the assertion makes that explicit for the
    # processor contract rather than suppressing the check.
    assert isinstance(scrubbed, MutableMapping)
    return scrubbed


def _context_processor(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    if (rid := request_id_var.get()) and "request_id" not in event_dict:
        event_dict["request_id"] = rid
    if (actor := actor_id_var.get()) and "actor_id" not in event_dict:
        event_dict["actor_id"] = actor
    if (org := org_id_var.get()) and "org_id" not in event_dict:
        event_dict["org_id"] = org
    return event_dict


_configured = False


def configure_logging(level: str | None = None, fmt: str | None = None) -> None:
    """Install the structlog pipeline. Idempotent."""
    global _configured
    settings = get_settings()
    level = (level or settings.log_level).upper()
    fmt = fmt or settings.log_format

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level, logging.INFO),
        force=True,
    )
    for noisy in ("uvicorn.access", "sqlalchemy.engine.Engine", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, getattr(logging, level)))

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if fmt == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _context_processor,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _redaction_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    if not _configured:
        configure_logging()
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
