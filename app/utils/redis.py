import hashlib
import json
from datetime import UTC, datetime

from redis.asyncio import Redis as AsyncRedis

from app.config import settings

redis_client: AsyncRedis | None = None


async def init_redis() -> AsyncRedis:
    global redis_client
    redis_client = AsyncRedis.from_url(str(settings.redis_url), decode_responses=True)
    return redis_client


async def close_redis() -> None:
    global redis_client
    if redis_client:
        await redis_client.aclose()
        redis_client = None


async def get_redis() -> AsyncRedis:
    if redis_client is None:
        return await init_redis()
    return redis_client


def _jti_key(jti: str) -> str:
    return f"blacklist:{jti}"


def _verify_cache_key(token: str) -> str:
    return f"verify:{hashlib.sha256(token.encode()).hexdigest()}"


async def blacklist_token(jti: str, expires_at: datetime) -> None:
    r = await get_redis()
    remaining = int((expires_at - datetime.now(UTC)).total_seconds())
    if remaining > 0:
        await r.setex(_jti_key(jti), remaining, "1")


async def is_blacklisted(jti: str) -> bool:
    r = await get_redis()
    return await r.exists(_jti_key(jti)) == 1


async def cache_verify(token: str, response: dict, ttl: int) -> None:
    r = await get_redis()
    await r.setex(_verify_cache_key(token), ttl, json.dumps(response, default=str))


async def get_cached_verify(token: str) -> dict | None:
    r = await get_redis()
    cached = await r.get(_verify_cache_key(token))
    return json.loads(cached) if cached else None


async def invalidate_user_cache(user_id: str) -> None:
    r = await get_redis()
    pattern = f"user:{user_id}:permissions"
    keys = await r.keys(pattern)
    if keys:
        await r.delete(*keys)
