"""Structured JSON logging for Hortus Clavis.

Standard (apply it in every new module)
---------------------------------------
1. ``logger = get_logger(__name__)`` at module level. Never ``print``.
2. ``message`` is a stable, snake_case event id (``auth.login_failed``,
   ``oidc.refresh_reuse_detected``, ``rbac.permission_denied``). It is meant to
   be grepped and counted, so it must not contain values — those go in ``props``.
3. ``extra={"props": {...}}`` carries the structured fields. Keep them flat and
   JSON-serialisable (``str``/``int``/``bool``/``list``/``dict``).
4. Where to log:
   * HTTP layer: the request middleware emits exactly one ``request`` line per
     call (see ``app.main``); routers only add protocol errors.
   * Service layer: state changes and refusals that matter for audit — login,
     token issuance/rejection, permission denial, client lifecycle, key rotation.
   * Pure helpers (``app/utils/oidc.py``, ``app/utils/security.py``): no logging.
     They have no context and would only duplicate their caller.
5. Never log secrets: passwords, access/id/refresh tokens, authorization codes,
   client secrets, private keys, session cookies. Log ids (``user_id``,
   ``client_id``, ``role_id``) and hashes instead. Never log the query string of
   an authorize request: it carries ``code``, ``state`` and ``code_challenge``.
6. Correlation is automatic: the middleware binds a request id and every line
   emitted during that request — service logs included — gets ``request_id``
   injected by the formatter. Callers never pass it down by hand.

``IAM_DEBUG=true`` lowers the level to DEBUG for our loggers.
"""

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from app.config import settings

#: Correlation id of the request being handled, bound by the HTTP middleware.
#: A contextvar keeps it out of every service signature and survives the awaits
#: of one request without leaking into another.
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)


class JSONFormatter(logging.Formatter):
    """Render a log record as a single JSON object.

    Shape: ``timestamp``, ``level``, ``logger``, ``message`` (event id),
    optional ``request_id``, then whatever the caller put in ``extra.props``.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = _request_id.get()
        if request_id:
            entry["request_id"] = request_id
        props = getattr(record, "props", None)
        if props:
            entry.update(props)
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def get_logger(name: str) -> logging.Logger:
    """Return a module logger wired to the JSON handler (idempotent).

    Safe to call at import time: the handler is attached once per logger name
    and the level follows ``settings.debug``.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    return logger


def bind_request_id(request_id: str) -> contextvars.Token:
    """Bind ``request_id`` for the current request; returns the reset token."""
    return _request_id.set(request_id)


def reset_request_id(token: contextvars.Token) -> None:
    """Restore the previous request id (called in the middleware ``finally``)."""
    _request_id.reset(token)


def current_request_id() -> str | None:
    """Return the request id bound to the current context, if any."""
    return _request_id.get()
