import uuid
from datetime import UTC, datetime, timedelta

import jwt
from passlib.hash import bcrypt

from app.config import settings


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.verify(password, password_hash)


def create_access_token(user_id: uuid.UUID, email: str) -> tuple[str, int]:
    now = datetime.now(UTC)
    expires_in = settings.jwt_expiration
    payload = {
        "sub": str(user_id),
        "email": email,
        "iss": "hortus-clavis",
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    return token, expires_in


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], issuer="hortus-clavis")
