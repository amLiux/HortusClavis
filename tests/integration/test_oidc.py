import base64
import hashlib
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.service import Service
from app.services import oidc as oidc_service

REDIRECT_URI = "http://localhost:3000/api/auth/callback/hortusclavis"
ISSUER = "http://localhost:8000"


async def _create_client(db_session, *, is_confidential: bool = True):
    service = (await db_session.execute(select(Service).where(Service.name == "iam"))).scalar_one()
    client, secret = await oidc_service.create_client(
        db_session,
        service_id=service.id,
        name="DevCadence",
        redirect_uris=[REDIRECT_URI],
        is_confidential=is_confidential,
    )
    await db_session.commit()
    return client, secret


async def _register(client: AsyncClient, email: str = "oidc@test.com") -> None:
    resp = await client.post(
        "/auth/register",
        json={"email": email, "password": "secret123", "name": "Oidc", "last_name": "User"},
    )
    assert resp.status_code == 200


def _pkce() -> tuple[str, str]:
    verifier = "v" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def _authorize_params(client_id: str, challenge: str, **extra) -> dict:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email offline_access hc.permissions",
        "state": "state-123",
        "nonce": "nonce-123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(extra)
    return params


async def _login_and_get_code(client: AsyncClient, params: dict, email: str) -> str:
    page = await client.get("/oidc/authorize", params=params)
    assert page.status_code == 200
    assert "<form" in page.text

    resp = await client.post(
        "/oidc/authorize",
        data={**params, "email": email, "password": "secret123"},
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = parse_qs(urlsplit(location).query)
    assert query["state"] == ["state-123"]
    return query["code"][0]


@pytest.mark.asyncio
async def test_discovery_document(client: AsyncClient):
    resp = await client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == ISSUER
    assert data["authorization_endpoint"] == f"{ISSUER}/oidc/authorize"
    assert data["token_endpoint"] == f"{ISSUER}/oidc/token"
    assert data["jwks_uri"] == f"{ISSUER}/oidc/jwks.json"
    assert data["code_challenge_methods_supported"] == ["S256"]


@pytest.mark.asyncio
async def test_jwks_publishes_rsa_key(client: AsyncClient):
    resp = await client.get("/oidc/jwks.json")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert keys
    key = keys[0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert "d" not in key


@pytest.mark.asyncio
async def test_authorization_code_flow_with_pkce(client: AsyncClient, db_session):
    await _register(client)
    oauth_client, secret = await _create_client(db_session)
    verifier, challenge = _pkce()
    params = _authorize_params(oauth_client.client_id, challenge)
    code = await _login_and_get_code(client, params, "oidc@test.com")

    token_resp = await client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(oauth_client.client_id, secret),
    )
    assert token_resp.status_code == 200, token_resp.text
    tokens = token_resp.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["access_token"]
    assert tokens["id_token"]
    assert tokens["refresh_token"]

    userinfo = await client.get(
        "/oidc/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert userinfo.status_code == 200
    data = userinfo.json()
    assert data["email"] == "oidc@test.com"
    assert data["sub"]
    assert data["hc.service"] == "iam"
    assert isinstance(data["hc.permissions"], list)

    id_token = tokens["id_token"]
    assert id_token.count(".") == 2


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_reuse_rejected(client: AsyncClient, db_session):
    await _register(client, "refresh@test.com")
    oauth_client, secret = await _create_client(db_session)
    verifier, challenge = _pkce()
    params = _authorize_params(oauth_client.client_id, challenge)
    code = await _login_and_get_code(client, params, "refresh@test.com")

    first = await client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(oauth_client.client_id, secret),
    )
    refresh_token = first.json()["refresh_token"]

    rotated = await client.post(
        "/oidc/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        auth=(oauth_client.client_id, secret),
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["refresh_token"] != refresh_token

    replay = await client.post(
        "/oidc/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        auth=(oauth_client.client_id, secret),
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_authorization_code_cannot_be_reused(client: AsyncClient, db_session):
    await _register(client, "reuse@test.com")
    oauth_client, secret = await _create_client(db_session)
    verifier, challenge = _pkce()
    params = _authorize_params(oauth_client.client_id, challenge)
    code = await _login_and_get_code(client, params, "reuse@test.com")

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }
    assert (
        await client.post("/oidc/token", data=payload, auth=(oauth_client.client_id, secret))
    ).status_code == 200
    second = await client.post("/oidc/token", data=payload, auth=(oauth_client.client_id, secret))
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_wrong_pkce_verifier_rejected(client: AsyncClient, db_session):
    await _register(client, "pkce@test.com")
    oauth_client, secret = await _create_client(db_session)
    _verifier, challenge = _pkce()
    params = _authorize_params(oauth_client.client_id, challenge)
    code = await _login_and_get_code(client, params, "pkce@test.com")

    resp = await client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "w" * 64,
        },
        auth=(oauth_client.client_id, secret),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_public_client_requires_pkce(client: AsyncClient, db_session):
    await _register(client, "public@test.com")
    oauth_client, secret = await _create_client(db_session, is_confidential=False)
    assert secret is None
    params = _authorize_params(oauth_client.client_id, "")
    params.pop("code_challenge")
    params.pop("code_challenge_method")

    page = await client.get("/oidc/authorize", params=params)
    assert page.status_code == 200

    resp = await client.post(
        "/oidc/authorize",
        data={**params, "email": "public@test.com", "password": "secret123"},
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "error=invalid_request" in location


@pytest.mark.asyncio
async def test_prompt_none_without_session_returns_login_required(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    _verifier, challenge = _pkce()
    params = _authorize_params(oauth_client.client_id, challenge, prompt="none")
    resp = await client.get("/oidc/authorize", params=params)
    assert resp.status_code == 302
    assert "error=login_required" in resp.headers["location"]


@pytest.mark.asyncio
async def test_unknown_redirect_uri_is_not_redirected(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    _, challenge = _pkce()
    params = _authorize_params(
        oauth_client.client_id, challenge, redirect_uri="https://evil.test/cb"
    )
    resp = await client.get("/oidc/authorize", params=params)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_token_endpoint_rejects_bad_client_secret(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    resp = await client.post(
        "/oidc/token",
        data={"grant_type": "authorization_code", "code": "x", "redirect_uri": REDIRECT_URI},
        auth=(oauth_client.client_id, "wrong-secret"),
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def _id_token_for(db_session, client_id: str, *, expires_in: int = 900) -> str:
    """Mint an ID token directly so logout can be tested without the code flow."""
    from app.utils.oidc import now, sign_rs256

    key = await oidc_service.ensure_signing_key(db_session)
    await db_session.commit()
    payload = {
        "iss": ISSUER,
        "sub": str(uuid.uuid4()),
        "aud": client_id,
        "iat": int(now().timestamp()),
        "exp": int((now() + timedelta(seconds=expires_in)).timestamp()),
        "token_use": "id",
    }
    return sign_rs256(payload, key.private_key_pem, key.kid)


@pytest.mark.asyncio
async def test_logout_with_client_id_redirects_and_clears_cookie(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    resp = await client.get(
        "/oidc/logout",
        params={
            "client_id": oauth_client.client_id,
            "post_logout_redirect_uri": REDIRECT_URI,
            "state": "bye-123",
        },
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = parse_qs(urlsplit(location).query)
    assert query["state"] == ["bye-123"]
    cookie = resp.headers.get("set-cookie", "")
    assert "hc_session=" in cookie
    assert "Max-Age=0" in cookie


@pytest.mark.asyncio
async def test_logout_with_unknown_client_id_is_rejected(client: AsyncClient, db_session):
    await _create_client(db_session)
    resp = await client.get(
        "/oidc/logout",
        params={"client_id": "hc_does_not_exist", "post_logout_redirect_uri": REDIRECT_URI},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_logout_without_client_identifier_is_rejected(client: AsyncClient, db_session):
    await _create_client(db_session)
    resp = await client.get(
        "/oidc/logout", params={"post_logout_redirect_uri": REDIRECT_URI}
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_logout_rejects_unregistered_post_logout_redirect(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    resp = await client.get(
        "/oidc/logout",
        params={
            "client_id": oauth_client.client_id,
            "post_logout_redirect_uri": "https://evil.test/bye",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_logout_with_id_token_hint_still_redirects(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    hint = await _id_token_for(db_session, oauth_client.client_id)
    resp = await client.get(
        "/oidc/logout",
        params={
            "id_token_hint": hint,
            "post_logout_redirect_uri": REDIRECT_URI,
            "state": "hint-123",
        },
    )
    assert resp.status_code == 302
    query = parse_qs(urlsplit(resp.headers["location"]).query)
    assert query["state"] == ["hint-123"]


@pytest.mark.asyncio
async def test_logout_falls_back_to_client_id_when_hint_is_expired(client: AsyncClient, db_session):
    oauth_client, _secret = await _create_client(db_session)
    hint = await _id_token_for(db_session, oauth_client.client_id, expires_in=-60)
    resp = await client.get(
        "/oidc/logout",
        params={
            "id_token_hint": hint,
            "client_id": oauth_client.client_id,
            "post_logout_redirect_uri": REDIRECT_URI,
        },
    )
    assert resp.status_code == 302
    assert resp.headers["location"].startswith(REDIRECT_URI)
