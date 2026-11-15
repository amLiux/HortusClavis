import uuid
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.authorization_code import AuthorizationCode
from app.models.oauth_client import OAuthClient
from app.models.refresh_token import RefreshToken
from app.models.service import Service
from app.models.signing_key import SigningKey
from app.models.users import User
from app.utils.oidc import (
    generate_rsa_key,
    hash_token,
    now,
    public_jwk_from_pem,
    random_token,
    sign_rs256,
    verify_pkce,
)
from app.utils.permissions import get_user_permissions
from app.utils.security import hash_password, verify_password

DEFAULT_SCOPES = "openid profile email offline_access hc.permissions"


class OAuthError(Exception):
    """An OIDC error that is safe to return to the client."""

    def __init__(self, error: str, description: str, status_code: int = 400):
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


async def ensure_signing_key(db: AsyncSession) -> SigningKey:
    key = await get_active_signing_key(db)
    if key:
        return key
    private_pem, kid, _jwk = generate_rsa_key()
    key = SigningKey(kid=kid, alg="RS256", private_key_pem=private_pem, is_active=True)
    db.add(key)
    await db.flush()
    return key


async def get_active_signing_key(db: AsyncSession) -> SigningKey | None:
    result = await db.execute(
        select(SigningKey)
        .where(SigningKey.is_active.is_(True))
        .order_by(SigningKey.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def rotate_signing_key(db: AsyncSession) -> SigningKey:
    """Create a new active key and retire the previous ones.

    Old keys stay published in JWKS until they are explicitly deleted, so
    in-flight tokens keep validating while clients refresh their cache.
    """
    previous = await db.execute(select(SigningKey).where(SigningKey.is_active.is_(True)))
    for old in previous.scalars().all():
        old.is_active = False
        old.retired_at = now()
    private_pem, kid, _jwk = generate_rsa_key()
    key = SigningKey(kid=kid, alg="RS256", private_key_pem=private_pem, is_active=True)
    db.add(key)
    await db.flush()
    return key


async def get_jwks(db: AsyncSession) -> dict:
    result = await db.execute(select(SigningKey).order_by(SigningKey.created_at.desc()))
    keys = [public_jwk_from_pem(k.private_key_pem, k.kid) for k in result.scalars().all()]
    return {"keys": keys}


async def get_signing_key_by_kid(db: AsyncSession, kid: str) -> SigningKey | None:
    result = await db.execute(select(SigningKey).where(SigningKey.kid == kid))
    return result.scalar_one_or_none()


async def get_client(db: AsyncSession, client_id: str) -> OAuthClient | None:
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    return result.scalar_one_or_none()


async def create_client(
    db: AsyncSession,
    *,
    service_id: uuid.UUID,
    name: str,
    redirect_uris: list[str],
    scopes: str = DEFAULT_SCOPES,
    is_confidential: bool = True,
) -> tuple[OAuthClient, str | None]:
    for uri in redirect_uris:
        if not uri.startswith(("http://", "https://")):
            raise ValueError(f"Invalid redirect URI: {uri}")

    client_id = f"hc_{random_token(12)}"
    plaintext_secret = f"hcs_{random_token(32)}" if is_confidential else None
    client = OAuthClient(
        client_id=client_id,
        client_secret_hash=hash_password(plaintext_secret) if plaintext_secret else None,
        name=name,
        service_id=service_id,
        redirect_uris=list(redirect_uris),
        scopes=scopes,
        is_confidential=is_confidential,
    )
    db.add(client)
    await db.flush()
    return client, plaintext_secret


def validate_redirect_uri(client: OAuthClient, redirect_uri: str) -> None:
    if redirect_uri not in (client.redirect_uris or []):
        raise OAuthError("invalid_request", "redirect_uri is not registered for this client")


def validate_scopes(client: OAuthClient, scope: str) -> set[str]:
    requested = {s for s in scope.split() if s}
    allowed = {s for s in client.scopes.split() if s}
    unknown = requested - allowed
    if unknown:
        raise OAuthError("invalid_scope", f"Scopes not allowed: {' '.join(sorted(unknown))}")
    return requested


def authenticate_client(client: OAuthClient | None, client_secret: str | None) -> OAuthClient:
    if not client:
        raise OAuthError("invalid_client", "Unknown client", status_code=401)
    if client.is_confidential:
        if not client_secret or not client.client_secret_hash:
            raise OAuthError("invalid_client", "Client authentication required", status_code=401)
        if not verify_password(client_secret, client.client_secret_hash):
            raise OAuthError("invalid_client", "Invalid client secret", status_code=401)
    return client


async def get_service_name(db: AsyncSession, service_id: uuid.UUID) -> str:
    result = await db.execute(select(Service.name).where(Service.id == service_id))
    name = result.scalar_one_or_none()
    if not name:
        raise OAuthError("server_error", "Client service not found", status_code=500)
    return name


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    """Validate email/password for the OIDC login form."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.password_hash):
        raise OAuthError("access_denied", "Invalid email or password")
    if not user.is_active:
        raise OAuthError("access_denied", "Account is inactive")
    return user


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def create_authorization_code(
    db: AsyncSession,
    *,
    user: User,
    client: OAuthClient,
    redirect_uri: str,
    scope: str,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> str:
    scopes = validate_scopes(client, scope)
    if "openid" not in scopes:
        raise OAuthError("invalid_scope", "The openid scope is required")
    if not client.is_confidential and not code_challenge:
        raise OAuthError("invalid_request", "PKCE code_challenge is required for public clients")
    if code_challenge and code_challenge_method not in ("S256", "plain"):
        raise OAuthError("invalid_request", "Unsupported code_challenge_method")
    if code_challenge_method == "plain":
        raise OAuthError("invalid_request", "Only S256 code challenges are accepted")

    raw_code = random_token(32)
    db.add(
        AuthorizationCode(
            code_hash=hash_token(raw_code),
            client_id=client.client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=" ".join(sorted(scopes)),
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=now() + timedelta(seconds=settings.oidc_authorization_code_expiration),
        )
    )
    await db.flush()
    return raw_code


async def consume_authorization_code(
    db: AsyncSession,
    *,
    raw_code: str,
    client: OAuthClient,
    redirect_uri: str,
    code_verifier: str | None,
) -> AuthorizationCode:
    result = await db.execute(
        select(AuthorizationCode).where(AuthorizationCode.code_hash == hash_token(raw_code))
    )
    code = result.scalar_one_or_none()
    if not code:
        raise OAuthError("invalid_grant", "Unknown authorization code")
    if code.client_id != client.client_id:
        raise OAuthError("invalid_grant", "Authorization code was issued to another client")
    if code.consumed_at is not None:
        raise OAuthError("invalid_grant", "Authorization code already used")
    if code.expires_at <= now():
        raise OAuthError("invalid_grant", "Authorization code expired")
    if code.redirect_uri != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri does not match the authorization request")
    if code.code_challenge:
        if not code_verifier:
            raise OAuthError("invalid_grant", "code_verifier is required")
        if not verify_pkce(code_verifier, code.code_challenge, code.code_challenge_method):
            raise OAuthError("invalid_grant", "Invalid code_verifier")

    code.consumed_at = now()
    await db.flush()
    return code


async def issue_tokens(
    db: AsyncSession,
    *,
    user: User,
    client: OAuthClient,
    scope: str,
    auth_time: int,
    nonce: str | None = None,
    include_refresh: bool = True,
) -> dict:
    scopes = {s for s in scope.split() if s}
    service_name = await get_service_name(db, client.service_id)
    permissions = await get_user_permissions(db, user.id)
    service_permissions = permissions.get(service_name, [])

    signed_at = now()
    key = await ensure_signing_key(db)
    claims = {
        "iss": settings.oidc_issuer,
        "sub": str(user.id),
        "aud": client.client_id,
        "client_id": client.client_id,
        "iat": int(signed_at.timestamp()),
        "exp": int(
            (signed_at + timedelta(seconds=settings.oidc_access_token_expiration)).timestamp()
        ),
        "jti": random_token(16),
        "scope": " ".join(sorted(scopes)),
        "token_use": "access",
        "hc.service": service_name,
    }
    if "hc.permissions" in scopes:
        claims["hc.permissions"] = service_permissions
    if "email" in scopes:
        claims["email"] = user.email
    if "profile" in scopes:
        claims["name"] = f"{user.name} {user.last_name}".strip()
        claims["preferred_username"] = user.email

    access_token = sign_rs256(claims, key.private_key_pem, key.kid)

    response: dict = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.oidc_access_token_expiration,
        "scope": " ".join(sorted(scopes)),
    }

    if "openid" in scopes:
        id_claims = {
            "iss": settings.oidc_issuer,
            "sub": str(user.id),
            "aud": client.client_id,
            "iat": int(signed_at.timestamp()),
            "exp": int(
                (signed_at + timedelta(seconds=settings.oidc_access_token_expiration)).timestamp()
            ),
            "auth_time": auth_time,
            "token_use": "id",
        }
        if nonce:
            id_claims["nonce"] = nonce
        if "email" in scopes:
            id_claims["email"] = user.email
            # Hortus Clavis has no email verification yet; be explicit about it.
            id_claims["email_verified"] = False
        if "profile" in scopes:
            id_claims["name"] = f"{user.name} {user.last_name}".strip()
            id_claims["preferred_username"] = user.email
        response["id_token"] = sign_rs256(id_claims, key.private_key_pem, key.kid)

    if include_refresh and "offline_access" in scopes:
        response["refresh_token"] = await _new_refresh_token(
            db, user=user, client=client, scope=" ".join(sorted(scopes))
        )

    return response


async def _new_refresh_token(
    db: AsyncSession,
    *,
    user: User,
    client: OAuthClient,
    scope: str,
    rotated_from: uuid.UUID | None = None,
) -> str:
    raw = random_token(32)
    db.add(
        RefreshToken(
            token_hash=hash_token(raw),
            client_id=client.client_id,
            user_id=user.id,
            scope=scope,
            expires_at=now() + timedelta(seconds=settings.oidc_refresh_token_expiration),
            rotated_from=rotated_from,
        )
    )
    await db.flush()
    return raw


async def refresh_tokens(
    db: AsyncSession,
    *,
    raw_token: str,
    client: OAuthClient,
) -> dict:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw_token))
    )
    token = result.scalar_one_or_none()
    if not token:
        raise OAuthError("invalid_grant", "Unknown refresh token")
    if token.client_id != client.client_id:
        raise OAuthError("invalid_grant", "Refresh token was issued to another client")
    if token.revoked_at is not None:
        raise OAuthError("invalid_grant", "Refresh token already used")
    if token.expires_at <= now():
        raise OAuthError("invalid_grant", "Refresh token expired")

    user_result = await db.execute(select(User).where(User.id == token.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise OAuthError("invalid_grant", "User is inactive")

    token.revoked_at = now()
    await db.flush()

    return await issue_tokens(
        db,
        user=user,
        client=client,
        scope=token.scope,
        auth_time=int(now().timestamp()),
        include_refresh=True,
    )


async def revoke_user_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
    )
    for token in result.scalars().all():
        token.revoked_at = now()
    await db.flush()


async def userinfo(db: AsyncSession, user: User, client: OAuthClient, scopes: set[str]) -> dict:
    service_name = await get_service_name(db, client.service_id)
    permissions = await get_user_permissions(db, user.id)
    data: dict = {"sub": str(user.id), "hc.service": service_name}
    if "email" in scopes:
        data["email"] = user.email
        data["email_verified"] = False
    if "profile" in scopes:
        data["name"] = f"{user.name} {user.last_name}".strip()
        data["preferred_username"] = user.email
        if user.avatar:
            data["picture"] = user.avatar
    if "hc.permissions" in scopes:
        data["hc.permissions"] = permissions.get(service_name, [])
    return data


def iso(value: datetime) -> str:
    return value.astimezone().isoformat()
