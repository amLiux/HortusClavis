import base64
import uuid
from pathlib import Path
from urllib.parse import unquote

import jwt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.services import oidc as oidc_service
from app.services.oidc import OAuthError
from app.utils.oidc import (
    SESSION_COOKIE,
    add_query_params,
    create_session_token,
    decode_rs256,
    decode_session,
    is_secure_url,
    public_pem_from_private,
)

router = APIRouter(tags=["oidc"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _error_response(error: OAuthError) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if error.error == "invalid_client":
        headers["WWW-Authenticate"] = "Basic"
    return JSONResponse(
        {"error": error.error, "error_description": error.description},
        status_code=error.status_code,
        headers=headers,
    )


def _redirect_error(
    redirect_uri: str, state: str | None, error: str, description: str
) -> RedirectResponse:
    url = add_query_params(
        redirect_uri,
        {"error": error, "error_description": description, "state": state},
    )
    return RedirectResponse(url, status_code=302)


def _session_cookie(response: RedirectResponse, user_id: uuid.UUID) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(str(user_id)),
        max_age=settings.oidc_session_expiration,
        httponly=True,
        samesite="lax",
        secure=is_secure_url(settings.oidc_issuer),
        path="/",
    )


async def _resolve_client(db: AsyncSession, client_id: str | None, redirect_uri: str | None):
    """Validate the client and redirect URI before redirecting any error."""
    if not client_id:
        raise OAuthError("invalid_request", "client_id is required")
    client = await oidc_service.get_client(db, client_id)
    if not client:
        raise OAuthError("invalid_client", "Unknown client", status_code=401)
    if not redirect_uri:
        raise OAuthError("invalid_request", "redirect_uri is required")
    oidc_service.validate_redirect_uri(client, redirect_uri)
    return client


@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    if not settings.oidc_enabled:
        raise OAuthError("not_found", "OIDC provider is disabled", status_code=404)
    issuer = settings.oidc_issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oidc/authorize",
        "token_endpoint": f"{issuer}/oidc/token",
        "userinfo_endpoint": f"{issuer}/oidc/userinfo",
        "jwks_uri": f"{issuer}/oidc/jwks.json",
        "end_session_endpoint": f"{issuer}/oidc/logout",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access", "hc.permissions"],
        "claims_supported": [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "email",
            "email_verified",
            "name",
            "preferred_username",
            "picture",
            "hc.service",
            "hc.permissions",
        ],
        "code_challenge_methods_supported": ["S256"],
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
    }


@router.get("/oidc/jwks.json")
async def jwks(db: AsyncSession = Depends(get_db)):
    await oidc_service.ensure_signing_key(db)
    keys = await oidc_service.get_jwks(db)
    return JSONResponse(keys, headers={"Cache-Control": "public, max-age=300"})


def _authorize_params(source) -> dict:
    keys = (
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "prompt",
    )
    return {key: source.get(key) or None for key in keys}


async def _issue_authorization_redirect(
    db: AsyncSession,
    *,
    user,
    client,
    params: dict,
) -> RedirectResponse:
    code = await oidc_service.create_authorization_code(
        db,
        user=user,
        client=client,
        redirect_uri=params["redirect_uri"],
        scope=params["scope"] or "openid",
        nonce=params["nonce"],
        code_challenge=params["code_challenge"],
        code_challenge_method=params["code_challenge_method"],
    )
    url = add_query_params(
        params["redirect_uri"],
        {"code": code, "state": params["state"]},
    )
    response = RedirectResponse(url, status_code=302)
    _session_cookie(response, user.id)
    return response


async def _authorize(db: AsyncSession, request: Request, params: dict):
    if not settings.oidc_enabled:
        raise OAuthError("not_found", "OIDC provider is disabled", status_code=404)

    client = await _resolve_client(db, params.get("client_id"), params.get("redirect_uri"))
    redirect_uri = params["redirect_uri"]
    state = params.get("state")

    try:
        if (params.get("response_type") or "code") != "code":
            raise OAuthError("unsupported_response_type", "Only response_type=code is supported")
        oidc_service.validate_scopes(client, params.get("scope") or "openid")
    except OAuthError as exc:
        return _redirect_error(redirect_uri, state, exc.error, exc.description)

    session = decode_session(request.cookies.get(SESSION_COOKIE, ""))
    if session and params.get("prompt") != "login":
        user = await oidc_service.get_user_by_id(db, uuid.UUID(session["sub"]))
        if user and user.is_active:
            try:
                return await _issue_authorization_redirect(
                    db,
                    user=user,
                    client=client,
                    params=params,
                )
            except OAuthError as exc:
                return _redirect_error(redirect_uri, state, exc.error, exc.description)

    if params.get("prompt") == "none":
        return _redirect_error(redirect_uri, state, "login_required", "No active browser session")

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "params": params,
            "error": None,
            "issuer": settings.oidc_issuer,
            "client_name": client.name,
        },
    )


@router.get("/oidc/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    try:
        return await _authorize(db, request, _authorize_params(request.query_params))
    except OAuthError as exc:
        return _error_response(exc)


@router.post("/oidc/authorize", response_class=HTMLResponse)
async def authorize_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    params = _authorize_params(form)
    try:
        if not settings.oidc_enabled:
            raise OAuthError("not_found", "OIDC provider is disabled", status_code=404)

        client = await _resolve_client(db, params.get("client_id"), params.get("redirect_uri"))
        redirect_uri = params["redirect_uri"]
        state = params.get("state")

        try:
            if (params.get("response_type") or "code") != "code":
                raise OAuthError(
                    "unsupported_response_type", "Only response_type=code is supported"
                )
            oidc_service.validate_scopes(client, params.get("scope") or "openid")
        except OAuthError as exc:
            return _redirect_error(redirect_uri, state, exc.error, exc.description)

        password = form.get("password") or ""
        user = await oidc_service.authenticate_user(db, str(form.get("email") or ""), str(password))
        try:
            return await _issue_authorization_redirect(
                db,
                user=user,
                client=client,
                params=params,
            )
        except OAuthError as exc:
            return _redirect_error(redirect_uri, state, exc.error, exc.description)
    except OAuthError as exc:
        if exc.error in ("invalid_client", "invalid_request", "not_found"):
            return _error_response(exc)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "params": params,
                "error": exc.description,
                "issuer": settings.oidc_issuer,
                "client_name": "",
            },
            status_code=exc.status_code if exc.status_code >= 400 else 401,
        )


def _parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    client_id, _, secret = raw.partition(":")
    return unquote(client_id), unquote(secret)


@router.post("/oidc/token")
async def token(request: Request, db: AsyncSession = Depends(get_db)):
    if not settings.oidc_enabled:
        return _error_response(
            OAuthError("not_found", "OIDC provider is disabled", status_code=404)
        )

    form = await request.form()
    grant_type = str(form.get("grant_type") or "")

    basic = _parse_basic_auth(request.headers.get("authorization"))
    client_id = basic[0] if basic else str(form.get("client_id") or "")
    client_secret = basic[1] if basic else str(form.get("client_secret") or "")

    try:
        client = await oidc_service.get_client(db, client_id)
        oidc_service.authenticate_client(client, client_secret or None)

        if grant_type == "authorization_code":
            if not client:
                raise OAuthError("invalid_client", "Unknown client", status_code=401)
            code = str(form.get("code") or "")
            redirect_uri = str(form.get("redirect_uri") or "")
            if not code or not redirect_uri:
                raise OAuthError("invalid_request", "code and redirect_uri are required")
            record = await oidc_service.consume_authorization_code(
                db,
                raw_code=code,
                client=client,
                redirect_uri=redirect_uri,
                code_verifier=str(form.get("code_verifier") or "") or None,
            )
            user = await oidc_service.get_user_by_id(db, record.user_id)
            if not user or not user.is_active:
                raise OAuthError("invalid_grant", "User is inactive")
            response = await oidc_service.issue_tokens(
                db,
                user=user,
                client=client,
                scope=record.scope,
                auth_time=int(record.created_at.timestamp()) if record.created_at else 0,
                nonce=record.nonce,
            )
        elif grant_type == "refresh_token":
            if not client:
                raise OAuthError("invalid_client", "Unknown client", status_code=401)
            raw_token = str(form.get("refresh_token") or "")
            if not raw_token:
                raise OAuthError("invalid_request", "refresh_token is required")
            response = await oidc_service.refresh_tokens(db, raw_token=raw_token, client=client)
        else:
            raise OAuthError("unsupported_grant_type", f"Unsupported grant_type: {grant_type}")

        return JSONResponse(response, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    except OAuthError as exc:
        return _error_response(exc)


@router.get("/oidc/userinfo")
async def userinfo_endpoint(request: Request, db: AsyncSession = Depends(get_db)):
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return _error_response(
            OAuthError("invalid_token", "Bearer token required", status_code=401)
        )
    raw_token = authorization[7:].strip()

    try:
        try:
            header = jwt.get_unverified_header(raw_token)
        except jwt.PyJWTError:
            raise OAuthError("invalid_token", "Malformed token", status_code=401) from None

        key = await oidc_service.get_signing_key_by_kid(db, str(header.get("kid") or ""))
        if not key:
            raise OAuthError("invalid_token", "Unknown signing key", status_code=401)

        payload = decode_rs256(raw_token, public_pem_from_private(key.private_key_pem))
        if payload.get("token_use") != "access":
            raise OAuthError("invalid_token", "Not an access token", status_code=401)

        client = await oidc_service.get_client(db, str(payload.get("aud") or ""))
        if not client:
            raise OAuthError("invalid_token", "Unknown audience", status_code=401)

        user = await oidc_service.get_user_by_id(db, uuid.UUID(str(payload["sub"])))
        if not user or not user.is_active:
            raise OAuthError("invalid_token", "User is inactive", status_code=401)

        scopes = {s for s in str(payload.get("scope", "")).split() if s}
        data = await oidc_service.userinfo(db, user, client, scopes)
    except OAuthError as exc:
        return _error_response(exc)
    except (jwt.PyJWTError, ValueError, KeyError):
        return _error_response(OAuthError("invalid_token", "Invalid token", status_code=401))

    headers = {"Cache-Control": "no-store"}
    return JSONResponse(data, headers=headers)


@router.get("/oidc/logout")
async def logout(
    id_token_hint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    target = None
    if post_logout_redirect_uri:
        client = None
        if id_token_hint:
            try:
                header = jwt.get_unverified_header(id_token_hint)
                key = await oidc_service.get_signing_key_by_kid(db, str(header.get("kid") or ""))
                if key:
                    payload = decode_rs256(
                        id_token_hint, public_pem_from_private(key.private_key_pem)
                    )
                    client = await oidc_service.get_client(db, str(payload.get("aud") or ""))
            except (jwt.PyJWTError, ValueError):
                client = None
        if not client or post_logout_redirect_uri not in (client.redirect_uris or []):
            return _error_response(
                OAuthError("invalid_request", "post_logout_redirect_uri is not registered")
            )
        target = add_query_params(post_logout_redirect_uri, {"state": state})

    response: RedirectResponse | JSONResponse
    if target:
        response = RedirectResponse(target, status_code=302)
    else:
        response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
