from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request

from app.database import async_session
from app.routers import admin, auth
from app.services.bootstrap import bootstrap
from app.utils.logger import get_logger
from app.utils.migrate import run_migrations
from app.utils.redis import close_redis, init_redis

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("server_started", extra={"props": {"service": "hortus-clavis"}})
    await init_redis()
    logger.info("redis_connected")

    await run_migrations()

    async with async_session() as db:
        await bootstrap(db)
        await db.commit()

    logger.info("bootstrap_complete")
    yield
    await close_redis()
    logger.info("redis_disconnected")


app = FastAPI(title="Hortus Clavis", version="0.1.0", lifespan=lifespan)
app.include_router(admin.router)
app.include_router(auth.router)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = str(uuid4())[:8]
    start = perf_counter()

    response = await call_next(request)

    elapsed = (perf_counter() - start) * 1000
    logger.info(
        "request",
        extra={
            "props": {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "ms": round(elapsed, 1),
            }
        },
    )
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}
