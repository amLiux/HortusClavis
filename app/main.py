import logging
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.config import settings
from app.database import async_session
from app.routers import admin, auth, oidc
from app.services import oidc as oidc_service
from app.services.bootstrap import bootstrap
from app.utils.logger import bind_request_id, get_logger, reset_request_id
from app.utils.migrate import run_migrations
from app.utils.redis import close_redis, init_redis

logger = get_logger(__name__)

#: Inbound request ids are reused for tracing, but only when they look safe:
#: this value ends up in every log line, so newlines and control characters
#: must never get through (log injection).
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def _request_id_for(request: Request) -> str:
    """Reuse the caller's request id when valid, otherwise generate one."""
    incoming = request.headers.get("x-request-id")
    if incoming and REQUEST_ID_PATTERN.match(incoming):
        return incoming
    return uuid4().hex[:12]


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Boot the service: Redis, migrations, bootstrap and signing key."""
    logger.info(
        "server_started",
        extra={
            "props": {
                "service": "hortus-clavis",
                "oidc_enabled": settings.oidc_enabled,
                "debug": settings.debug,
                "issuer": settings.oidc_issuer,
            }
        },
    )
    await init_redis()
    await run_migrations()

    async with async_session() as db:
        await bootstrap(db)
        await oidc_service.ensure_signing_key(db)
        await db.commit()

    logger.info("bootstrap_complete")
    yield
    await close_redis()
    logger.info("server_stopped")


app = FastAPI(title="Hortus Clavis", version="0.1.0", lifespan=lifespan)
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(oidc.router)


@app.middleware("http")
async def log_requests(request: Request, call_next) -> Response:
    """Emit exactly one structured line per request, failures included.

    Binds a request id for the whole call (so service logs correlate), echoes it
    as ``X-Request-ID`` and never touches the query string — it can carry
    authorization codes, state and PKCE challenges.
    """
    request_id = _request_id_for(request)
    token = bind_request_id(request_id)
    start = perf_counter()
    status = 500
    failure: Exception | None = None

    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    except Exception as exc:  # noqa: BLE001 - observed, then re-raised untouched
        failure = exc
        raise
    finally:
        props = {
            # Also on the record (not only formatter-injected) so log shippers
            # that re-emit records outside the request context keep the id.
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": status,
            "ms": round((perf_counter() - start) * 1000, 1),
            "client_ip": request.client.host if request.client else None,
        }
        if failure is not None:
            props["error"] = type(failure).__name__
            logger.error(
                "request_failed",
                extra={"props": props},
                exc_info=(type(failure), failure, failure.__traceback__),
            )
        else:
            logger.log(
                logging.WARNING if status >= 500 else logging.INFO,
                "request",
                extra={"props": props},
            )
        reset_request_id(token)


@app.get("/health")
async def health():
    return {"status": "ok"}
