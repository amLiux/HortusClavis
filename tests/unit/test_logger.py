import json
import logging

import pytest
from starlette.requests import Request

from app.main import log_requests
from app.utils.logger import (
    JSONFormatter,
    bind_request_id,
    current_request_id,
    get_logger,
    reset_request_id,
)


def _record(message: str = "auth.login_failed", **props) -> logging.LogRecord:
    record = logging.LogRecord(
        name="app.services.auth",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    record.props = props
    return record


def test_formatter_emits_one_json_object_per_line():
    line = JSONFormatter().format(_record(user_id="u1", reason="invalid_credentials"))
    data = json.loads(line)

    assert "\n" not in line
    assert data["message"] == "auth.login_failed"
    assert data["level"] == "INFO"
    assert data["logger"] == "app.services.auth"
    assert data["user_id"] == "u1"
    assert data["reason"] == "invalid_credentials"
    assert data["timestamp"].endswith("+00:00")


def test_formatter_injects_bound_request_id():
    token = bind_request_id("abc123abc123")
    try:
        data = json.loads(JSONFormatter().format(_record()))
    finally:
        reset_request_id(token)

    assert data["request_id"] == "abc123abc123"
    assert current_request_id() is None


def test_get_logger_is_idempotent():
    first = get_logger("test.idempotent")
    second = get_logger("test.idempotent")

    assert first is second
    assert len(first.handlers) == 1
    assert isinstance(first.handlers[0].formatter, JSONFormatter)


def test_get_logger_follows_debug_setting():
    from app.config import settings

    logger = get_logger("test.level")
    assert logger.level == (logging.DEBUG if settings.debug else logging.INFO)


def _request(path: str = "/health") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("203.0.113.7", 51234),
            "server": ("test", 80),
        }
    )


async def test_middleware_logs_exactly_one_line_per_request(caplog):
    caplog.set_level(logging.INFO, logger="app.main")

    async def call_next(_request):
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok"})

    await log_requests(_request(), call_next)
    requests = [r for r in caplog.records if r.getMessage() == "request"]

    assert len(requests) == 1
    props = requests[0].props
    assert props["path"] == "/health"
    assert props["status"] == 200
    assert props["client_ip"] == "203.0.113.7"
    assert props["ms"] >= 0


async def test_middleware_logs_failures_with_traceback(caplog):
    caplog.set_level(logging.INFO, logger="app.main")

    async def call_next(_request):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await log_requests(_request("/boom"), call_next)

    failed = [r for r in caplog.records if r.getMessage() == "request_failed"]
    assert len(failed) == 1
    assert failed[0].props["status"] == 500
    assert failed[0].props["error"] == "RuntimeError"
    assert failed[0].exc_info is not None
    # no half-written "request" line next to it
    assert not [r for r in caplog.records if r.getMessage() == "request"]
