"""Business rules for the OIDC provider.

Everything in this module is independent of HTTP. The router turns a request
into a call here and translates :class:`OAuthError` into a response, so the
router never inspects a database row, hashes a secret or parses a token.

Conventions:

* Functions raise :class:`OAuthError` for every condition that may be reported
  to the client; the message is safe to return in ``error_description``.
* Reads return ``None`` when the row is missing, writes ``flush()`` but never
  ``commit()`` — the request-scoped session owns the transaction.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
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
    decode_rs256,
    generate_rsa_key,
    hash_token,
    now,
    public_jwk_from_pem,
    public_pem_from_private,
    random_token,
    sign_rs256,
    verify_pkce,
)
from app.utils.permissions import get_user_permissions
from app.utils.security import hash_password, verify_password

DEFAULT_SCOPES = "openid profile email offline_access hc.permissions"


class OAuthError(Exception):
    """An OIDC error that is safe to return to the client.

    ``error`` is the RFC 6749 error code, ``description`` the human readable
    text and ``status_code`` the HTTP status the router should use.
    """

    def __init__(self, error: str, description: str, status_code: int = 400):
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


@dataclass(frozen=True)
class AccessTokenContext:
    """Owner, client and granted scopes of a validated access token.

    Returned by :func:`validate_access_token` so the caller does not have to
    re-read the JWT claims.
    """

    user: User
    client: OAuthClient
    scopes: set[str]


# ---------------------------------------------------------------------------
# Signing keys
# ---------------------------------------------------------------------------


async def ensure_signing_key(db: AsyncSession) -> SigningKey:
    """Return the active signing key, creating one on first use.

    Called from the app lifespan and from the JWKS endpoint, so a fresh
    database always has a key before the first token is issued.
    """
    key = await get_active_signing_key(db)
    if key:
        return key
    private_pem, kid, _jwk = generate_rsa_key()
    key = SigningKey(kid=kid, alg="RS256", private_key_pem=private_pem, is_active=True)
    db.add(key)
    await db.flush()
    return key


async def get_active_signing_key(db: AsyncSession) -> SigningKey | None:
    """Return the newest active signing key, or ``None`` if none is configured."""
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
    """Return every published key as a JWKS document (public halves only).

    Retired keys are included on purpose: tokens signed with them must keep
    verifying until they expire.
    """
    result = await db.execute(select(SigningKey).order_by(SigningKey.created_at.desc()))
    keys = [public_jwk_from_pem(k.private_key_pem, k.kid) for k in result.scalars().all()]
    return {"keys": keys}


async def get_signing_key_by_kid(db: AsyncSession, kid: str) -> SigningKey | None:
    """Look up a signing key by its ``kid`` header value."""
    result = await db.execute(select(SigningKey).where(SigningKey.kid == kid))
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


async def get_client(db: AsyncSession, client_id: str) -> OAuthClient | None:
    """Look up an OAuth client by its public ``client_id``."""
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
    """Register a new client and return it with its plaintext secret.

    The secret is returned exactly once (only its bcrypt hash is stored);
    public clients get ``None`` and must use PKCE.
    """
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
    """Ensure ``redirect_uri`` is registered for this client (exact match).

    Nothing may be redirected before this check passes, otherwise the provider
    becomes an open redirector.
    """
    if redirect_uri not in (client.redirect_uris or []):
        raise OAuthError("invalid_request", "redirect_uri is not registered for this client")


def validate_scopes(client: OAuthClient, scope: str) -> set[str]:
    """Return the requested scopes, rejecting any the client is not allowed."""
    requested = {s for s in scope.split() if s}
    allowed = {s for s in client.scopes.split() if s}
    unknown = requested - allowed
    if unknown:
        raise OAuthError("invalid_scope", f"Scopes not allowed: {' '.join(sorted(unknown))}")
    return requested


def authenticate_client(client: OAuthClient | None, client_secret: str | None) -> OAuthClient:
    """Authenticate a confidential client, or return a public client unchanged.

    Raises ``invalid_client`` (401) for unknown clients, missing secrets and
    wrong secrets. Public clients carry no secret and are verified by PKCE at
    the token endpoint instead.
    """
    if not client:
        raise OAuthError("invalid_client", "Unknown client", status_code=401)
    if client.is_confidential:
        if not client_secret or not client.client_secret_hash:
            raise OAuthError("invalid_client", "Client authentication required", status_code=401)
        if not verify_password(client_secret, client.client_secret_hash):
            raise OAuthError("invalid_client", "Invalid client secret", status_code=401)
    return client


async def resolve_client(
    db: AsyncSession, client_id: str | None, redirect_uri: str | None
) -> OAuthClient:
    """Load and validate the client behind an authorization request.

    Must run before anything is redirected: a bad ``client_id`` or an
    unregistered ``redirect_uri`` has to be answered on our own page, never by
    redirecting to the client.
    """
    if not client_id:
        raise OAuthError("invalid_request", "client_id is required")
    client = await get_client(db, client_id)
    if not client:
        raise OAuthError("invalid_client", "Unknown client", status_code=401)
    if not redirect_uri:
        raise OAuthError("invalid_request", "redirect_uri is required")
    validate_redirect_uri(client, redirect_uri)
    return client


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


async def get_service_name(db: AsyncSession, service_id: uuid.UUID) -> str:
    """Return the tenant name that owns a client, used for the ``hc.service`` claim."""
    result = await db.execute(select(Service.name).where(Service.id == service_id))
    name = result.scalar_one_or_none()
    if not name:
        raise OAuthError("server_error", "Client service not found", status_code=500)
    return name


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    """Validate email/password for the OIDC login form.

    Raises ``access_denied`` with the same message for unknown users and wrong
    passwords so the form does not disclose which accounts exist.
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.password_hash):
        raise OAuthError("access_denied", "Invalid email or password")
    if not user.is_active:
        raise OAuthError("access_denied", "Account is inactive")
    return user


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Look up an active or inactive user by primary key."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Authorization request
# ---------------------------------------------------------------------------


def validate_authorize_request(client: OAuthClient, params: dict) -> set[str]:
    """Validate ``response_type`` and ``scope`` of an authorization request.

    Called once the client is trusted, because a failure here is reported back
    to the client's registered ``redirect_uri`` as ``error``/``error_description``.
    """
    if (params.get("response_type") or "code") != "code":
        raise OAuthError("unsupported_response_type", "Only response_type=code is supported")
    return validate_scopes(client, params.get("scope") or "openid")


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
    """Persist an authorization code and return its plaintext value.

    Only the SHA-256 hash is stored. Enforces the ``openid`` scope, PKCE for
    public clients and S256 as the only accepted challenge method.
    """
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
    """Redeem an authorization code exactly once, verifying PKCE.

    The row is marked ``consumed_at`` before returning, so a replay of the same
    code fails with ``invalid_grant``.
    """
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


async def exchange_authorization_code(
    db: AsyncSession,
    *,
    client: OAuthClient,
    raw_code: str,
    redirect_uri: str,
    code_verifier: str | None,
) -> dict:
    """Full ``authorization_code`` grant: consume the code and mint the tokens.

    Returns the token response body. Raises ``invalid_request`` when the grant
    is incomplete and ``invalid_grant`` when the code or its owner is unusable.
    """
    if not raw_code or not redirect_uri:
        raise OAuthError("invalid_request", "code and redirect_uri are required")

    record = await consume_authorization_code(
        db,
        raw_code=raw_code,
        client=client,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )
    user = await get_user_by_id(db, record.user_id)
    if not user or not user.is_active:
        raise OAuthError("invalid_grant", "User is inactive")

    return await issue_tokens(
        db,
        user=user,
        client=client,
        scope=record.scope,
        auth_time=int(record.created_at.timestamp()) if record.created_at else 0,
        nonce=record.nonce,
    )


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


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
    """Mint an access token, and the optional id/refresh tokens.

    Access tokens are RS256 JWTs with ``token_use=access``; the id token is
    only added for the ``openid`` scope and the refresh token only for
    ``offline_access``. Claims are filtered by the granted scopes.
    """
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
    """Persist a refresh token (hash only) and return its plaintext value.

    ``rotated_from`` links a rotated token to the one it replaced, so a whole
    rotation chain can be traced or revoked later.
    """
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
    """Rotate a refresh token: revoke it and issue a fresh token set.

    Reuse of an already revoked token is rejected (``invalid_grant``), which is
    what detects a stolen token being replayed after rotation.
    """
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


async def validate_access_token(db: AsyncSession, raw_token: str) -> AccessTokenContext:
    """Verify a bearer access token and return its owner, client and scopes.

    Checks, in order: JWT structure, known ``kid``, RS256 signature, issuer and
    expiry, ``token_use=access``, audience (must be a registered client) and
    that the user still exists and is active. Every failure becomes
    ``invalid_token`` (401) so the caller cannot distinguish the reasons.
    """
    try:
        header = jwt.get_unverified_header(raw_token)
    except jwt.PyJWTError:
        raise OAuthError("invalid_token", "Malformed token", status_code=401) from None

    key = await get_signing_key_by_kid(db, str(header.get("kid") or ""))
    if not key:
        raise OAuthError("invalid_token", "Unknown signing key", status_code=401)

    try:
        payload = decode_rs256(raw_token, public_pem_from_private(key.private_key_pem))
    except jwt.PyJWTError:
        raise OAuthError("invalid_token", "Invalid token", status_code=401) from None

    if payload.get("token_use") != "access":
        raise OAuthError("invalid_token", "Not an access token", status_code=401)

    client = await get_client(db, str(payload.get("aud") or ""))
    if not client:
        raise OAuthError("invalid_token", "Unknown audience", status_code=401)

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError):
        raise OAuthError("invalid_token", "Invalid token", status_code=401) from None

    user = await get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise OAuthError("invalid_token", "User is inactive", status_code=401)

    scopes = {s for s in str(payload.get("scope", "")).split() if s}
    return AccessTokenContext(user=user, client=client, scopes=scopes)


async def revoke_user_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Revoke every outstanding refresh token of a user (bulk logout)."""
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
    )
    for token in result.scalars().all():
        token.revoked_at = now()
    await db.flush()


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


async def _client_from_id_token(db: AsyncSession, id_token_hint: str | None) -> OAuthClient | None:
    """Return the client that owns ``id_token_hint``, or ``None`` if unusable.

    The signature, issuer and expiry are verified; any problem (malformed
    token, rotated-away key, unknown audience) is treated as "no client" so the
    caller can fall back to rejecting the redirect.
    """
    if not id_token_hint:
        return None
    try:
        header = jwt.get_unverified_header(id_token_hint)
    except jwt.PyJWTError:
        return None
    key = await get_signing_key_by_kid(db, str(header.get("kid") or ""))
    if not key:
        return None
    try:
        payload = decode_rs256(id_token_hint, public_pem_from_private(key.private_key_pem))
    except jwt.PyJWTError:
        return None
    return await get_client(db, str(payload.get("aud") or ""))


async def resolve_logout_redirect(
    db: AsyncSession,
    *,
    id_token_hint: str | None,
    post_logout_redirect_uri: str,
) -> str:
    """Validate the RP's ``post_logout_redirect_uri`` and return it unchanged.

    The URI must be registered for the client that owns ``id_token_hint``;
    otherwise this raises ``invalid_request`` and the caller must not redirect
    (open-redirect guard for RP-initiated logout).
    """
    client = await _client_from_id_token(db, id_token_hint)
    if not client or post_logout_redirect_uri not in (client.redirect_uris or []):
        raise OAuthError("invalid_request", "post_logout_redirect_uri is not registered")
    return post_logout_redirect_uri


# ---------------------------------------------------------------------------
# UserInfo
# ---------------------------------------------------------------------------


async def userinfo(db: AsyncSession, user: User, client: OAuthClient, scopes: set[str]) -> dict:
    """Build the UserInfo response filtered by the granted scopes.

    ``sub`` and ``hc.service`` are always present; ``email``/``profile`` and
    ``hc.permissions`` depend on the scopes the access token carries.
    """
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
    """Format a datetime as an ISO 8601 string in local time (admin responses)."""
    return value.astimezone().isoformat()
