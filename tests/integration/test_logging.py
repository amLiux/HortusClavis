import logging

import pytest
from httpx import AsyncClient


async def test_request_id_is_generated_and_echoed(client: AsyncClient):
    resp = await client.get("/health")

    assert resp.status_code == 200
    request_id = resp.headers.get("x-request-id")
    assert request_id and len(request_id) == 12


async def test_inbound_request_id_is_reused(client: AsyncClient):
    resp = await client.get("/health", headers={"X-Request-ID": "trace-abc-123"})

    assert resp.headers["x-request-id"] == "trace-abc-123"


@pytest.mark.parametrize(
    "incoming",
    ["short", "bad value with spaces", "nl\nInjected: yes", "x" * 80],
)
async def test_invalid_inbound_request_id_is_replaced(client: AsyncClient, incoming: str):
    resp = await client.get("/health", headers={"X-Request-ID": incoming})

    assert resp.headers["x-request-id"] != incoming
    assert len(resp.headers["x-request-id"]) == 12


async def test_each_request_logs_one_line_with_the_same_id(client: AsyncClient, caplog):
    caplog.set_level(logging.INFO, logger="app.main")

    resp = await client.get("/health")
    request_id = resp.headers["x-request-id"]
    lines = [r for r in caplog.records if r.getMessage() == "request"]

    assert len(lines) == 1
    props = lines[0].props
    assert props["path"] == "/health"
    assert props["status"] == 200
    # correlation: the id the client received is the one in the log line
    assert props["request_id"] == request_id


async def test_query_string_is_never_logged(client: AsyncClient, caplog):
    caplog.set_level(logging.INFO, logger="app.main")

    await client.get("/.well-known/openid-configuration?code=SECRET_CODE&state=s1")

    lines = [r for r in caplog.records if r.getMessage() == "request"]
    assert lines
    assert "SECRET_CODE" not in str(lines[0].props)
    assert "state=s1" not in str(lines[0].props)
