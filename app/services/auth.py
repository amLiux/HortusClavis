from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.users import User
from app.utils.permissions import get_user_permissions
from app.utils.redis import (
    blacklist_token,
    cache_verify,
    delete_cached_verify,
    get_cached_verify,
    is_blacklisted,
)
from app.utils.security import create_access_token, decode_access_token, verify_password


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def authenticate(self, email: str, password: str) -> tuple[str, int]:
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(401, "Invalid email or password")
        if not user.is_active:
            raise HTTPException(403, "Account is inactive")
        token, expires_in = create_access_token(user.id, user.email)
        return token, expires_in

    async def verify(self, token: str) -> dict:
        try:
            payload = decode_access_token(token)
        except Exception:
            raise HTTPException(401, "Invalid or expired token") from None

        jti = payload.get("jti")
        if jti and await is_blacklisted(jti):
            raise HTTPException(401, "Token has been revoked")

        cached = await get_cached_verify(token)
        if cached:
            return cached

        user_id = payload["sub"]

        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(401, "User not found")
        if not user.is_active:
            raise HTTPException(403, "Account is inactive")

        permissions = await get_user_permissions(self.db, user.id)

        expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)
        response = {
            "authenticated": True,
            "auth_type": "user",
            "user": {
                "id": str(user.id),
                "name": f"{user.name} {user.last_name}".strip(),
                "email": user.email,
            },
            "permissions": permissions,
            "expires_at": expires_at.isoformat(),
        }

        ttl = int((expires_at - datetime.now(UTC)).total_seconds())
        if ttl > 0:
            await cache_verify(token, response, ttl)

        return response

    async def logout(self, token: str) -> None:
        try:
            payload = decode_access_token(token)
        except Exception:
            raise HTTPException(401, "Invalid token") from None
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            await blacklist_token(jti, datetime.fromtimestamp(exp, tz=UTC))
        await delete_cached_verify(token)
