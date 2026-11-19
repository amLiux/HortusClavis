"""OIDC provider endpoints.

This module is the HTTP edge and nothing else: it reads the request, calls
``app.services.oidc`` and shapes the response. Validation rules, token issuance
and persistence live in the service layer; parsing and encoding live in
``app.utils.oidc``.

The only functions here that are not handlers are the four ``_`` helpers
below, and all of them build HTTP responses (status codes, headers, cookies,
templates).

Logging (the pattern HC-07 extends to the rest of the app)
----------------------------------------------------------
``message`` is a snake_case event id and the details go in
``extra={"props": {...}}``: ``oidc.login_succeeded``, ``oidc.login_failed``,
``oidc.code_issued``, ``oidc.tokens_issued``, ``oidc.client_auth_failed``,
``oidc.refresh_reuse_detected``, ``oidc.access_token_rejected``,
``oidc.logout``, plus ``oidc.request_rejected`` for every JSON error response.
Only ids are logged — never tokens, authorization codes, client secrets,
passwords or the request query string.
"""

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.services import oidc as oidc_service
from app.services.oidc import OAuthError
from app.utils.logger import get_logger
from app.utils.oidc import (
    SESSION_COOKIE,
    add_query_params,
    create_session_token,
    decode_session,
    extract_authorize_params,
    extract_bearer_token,
    is_secure_url,
    parse_basic_auth,
)

logger = get_logger(__name__)

router = APIRouter(tags=["oidc"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

#: Errors that must be rendered as JSON, never on the login page: at that point
#: we either do not know the client or already failed to validate it.
_JSON_ONLY_ERRORS = frozenset({"invalid_client", "invalid_request", "not_found"})


# ---------------------------------------------------------------------------
# HTTP response helpers (no business logic)
# ---------------------------------------------------------------------------


def _error_response(error: OAuthError) -> JSONResponse:
    """Render an :class:`OAuthError` as the RFC 6749 JSON error body.

    Adds ``Cache-Control: no-store`` and, for client authentication failures, a
    ``WWW-Authenticate: Basic`` challenge.
    """
    logger.warning(
        "oidc.request_rejected",
        extra={
            "props": {
                "error": error.error,
                "description": error.description,
                "status": error.status_code,
            }
        },
    )
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
    """Send an error back to the client's redirect_uri, echoing ``state``.

    Only used after the client and its redirect_uri have been validated.
    """
    logger.info(
        "oidc.authorize_error_redirect",
        extra={"props": {"error": error, "description": description}},
    )
    url = add_query_params(
        redirect_uri,
        {"error": error, "error_description": description, "state": state},
    )
    return RedirectResponse(url, status_code=302)


def _set_session_cookie(response: Response, user_id: uuid.UUID) -> None:
    """Attach the browser session cookie (HttpOnly, SameSite=Lax, Secure on HTTPS)."""
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(str(user_id)),
        max_age=settings.oidc_session_expiration,
        httponly=True,
        samesite="lax",
        secure=is_secure_url(settings.oidc_issuer),
        path="/",
    )


def _login_page(
    request: Request,
    params: dict,
    client_name: str,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    """Render the minimal login form, optionally with an error message."""
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "params": params,
            "error": error,
            "issuer": settings.oidc_issuer,
            "client_name": client_name,
        },
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Shared authorize flow
# ---------------------------------------------------------------------------


async def _code_redirect(
    db: AsyncSession,
    *,
    user,
    client,
    params: dict,
) -> Response:
    """Issue a single-use authorization code and redirect back to the client.

    Also starts the browser session. Failures while creating the code (bad PKCE,
    missing openid scope) are reported to the client as a redirect error.
    """
    try:
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
    except OAuthError as exc:
        return _redirect_error(
            params["redirect_uri"], params.get("state"), exc.error, exc.description
        )

    url = add_query_params(
        params["redirect_uri"],
        {"code": code, "state": params.get("state")},
    )
    response = RedirectResponse(url, status_code=302)
    _set_session_cookie(response, user.id)
    return response


async def _authorize_flow(
    db: AsyncSession,
    request: Request,
    params: dict,
    *,
    credentials: dict | None = None,
) -> Response:
    """Body shared by ``GET`` and ``POST /oidc/authorize``.

    With ``credentials`` (the submitted login form) it authenticates the user
    and issues a code. Without them it uses the browser session when present and
    otherwise renders the login page. ``prompt=login`` forces the form,
    ``prompt=none`` fails with ``login_required`` instead of prompting.
    """
    try:
        if not settings.oidc_enabled:
            raise OAuthError("not_found", "OIDC provider is disabled", status_code=404)

        client = await oidc_service.resolve_client(
            db, params.get("client_id"), params.get("redirect_uri")
        )
        redirect_uri = params["redirect_uri"]
        state = params.get("state")

        try:
            oidc_service.validate_authorize_request(client, params)
        except OAuthError as exc:
            return _redirect_error(redirect_uri, state, exc.error, exc.description)

        if credentials is not None:
            user = await oidc_service.authenticate_user(
                db, credentials["email"], credentials["password"]
            )
            return await _code_redirect(db, user=user, client=client, params=params)

        session = decode_session(request.cookies.get(SESSION_COOKIE, ""))
        if session and params.get("prompt") != "login":
            user = await oidc_service.get_user_by_id(db, uuid.UUID(session["sub"]))
            if user and user.is_active:
                return await _code_redirect(db, user=user, client=client, params=params)

        if params.get("prompt") == "none":
            return _redirect_error(
                redirect_uri, state, "login_required", "No active browser session"
            )

        return _login_page(request, params, client.name)
    except OAuthError as exc:
        # Bad credentials are a form error; everything else is a protocol error.
        if credentials is not None and exc.error not in _JSON_ONLY_ERRORS:
            return _login_page(request, params, "", error=exc.description, status_code=401)
        return _error_response(exc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict:
    """Serve the OpenID Provider metadata document (OIDC Discovery 1.0).

    Advertises the issuer, the five endpoints, the supported grant types,
    scopes and claims. Returns 404 when the provider is disabled.
    """
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
async def jwks(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Publish the public half of every signing key as a JWKS.

    Creates a key on first call so a fresh deployment is usable immediately.
    Cached for 5 minutes; rotated keys stay listed until their tokens expire.
    """
    await oidc_service.ensure_signing_key(db)
    keys = await oidc_service.get_jwks(db)
    return JSONResponse(keys, headers={"Cache-Control": "public, max-age=300"})


@router.get("/oidc/authorize", response_class=HTMLResponse)
async def authorize(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Start an authorization-code flow from query parameters.

    Redirects with a fresh code when the browser already has a session,
    otherwise renders the login form.
    """
    return await _authorize_flow(db, request, extract_authorize_params(request.query_params))


@router.post("/oidc/authorize", response_class=HTMLResponse)
async def authorize_submit(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Handle the login form submission and issue the authorization code.

    Bad credentials re-render the form with an error (401); protocol errors
    (unknown client, unregistered redirect_uri) are returned as JSON.
    """
    form = await request.form()
    params = extract_authorize_params(form)
    credentials = {
        "email": str(form.get("email") or ""),
        "password": str(form.get("password") or ""),
    }
    return await _authorize_flow(db, request, params, credentials=credentials)


@router.post("/oidc/token")
async def token(request: Request, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Token endpoint for the ``authorization_code`` and ``refresh_token`` grants.

    Client credentials come from HTTP Basic or the form body (RFC 6749 §2.3.1).
    Always answers with ``Cache-Control: no-store`` and never leaks which check
    failed beyond the OAuth error code.
    """
    if not settings.oidc_enabled:
        return _error_response(
            OAuthError("not_found", "OIDC provider is disabled", status_code=404)
        )

    form = await request.form()
    grant_type = str(form.get("grant_type") or "")
    basic = parse_basic_auth(request.headers.get("authorization"))
    client_id = basic[0] if basic else str(form.get("client_id") or "")
    client_secret = basic[1] if basic else str(form.get("client_secret") or "")

    try:
        client = oidc_service.authenticate_client(
            await oidc_service.get_client(db, client_id), client_secret or None
        )

        if grant_type == "authorization_code":
            payload = await oidc_service.exchange_authorization_code(
                db,
                client=client,
                raw_code=str(form.get("code") or ""),
                redirect_uri=str(form.get("redirect_uri") or ""),
                code_verifier=str(form.get("code_verifier") or "") or None,
            )
        elif grant_type == "refresh_token":
            raw_token = str(form.get("refresh_token") or "")
            if not raw_token:
                raise OAuthError("invalid_request", "refresh_token is required")
            payload = await oidc_service.refresh_tokens(db, raw_token=raw_token, client=client)
        else:
            raise OAuthError("unsupported_grant_type", f"Unsupported grant_type: {grant_type}")

        return JSONResponse(payload, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    except OAuthError as exc:
        return _error_response(exc)


@router.get("/oidc/userinfo")
async def userinfo_endpoint(request: Request, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Return claims about the user owning the presented access token.

    Requires ``Authorization: Bearer <access token>``; the token is validated
    and the claims are filtered by its scopes in the service layer.
    """
    raw_token = extract_bearer_token(request.headers.get("authorization"))
    if not raw_token:
        return _error_response(
            OAuthError("invalid_token", "Bearer token required", status_code=401)
        )

    try:
        context = await oidc_service.validate_access_token(db, raw_token)
        data = await oidc_service.userinfo(db, context.user, context.client, context.scopes)
    except OAuthError as exc:
        return _error_response(exc)

    return JSONResponse(data, headers={"Cache-Control": "no-store"})


@router.get("/oidc/logout")
async def logout(
    id_token_hint: str | None = None,
    client_id: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """RP-initiated logout: clear the browser session and optionally bounce back.

    ``post_logout_redirect_uri`` is only honoured when it is registered for the
    client that owns ``id_token_hint``; otherwise the request is rejected and the
    session cookie is left untouched.
    """
    target = None
    if post_logout_redirect_uri:
        try:
            redirect_uri = await oidc_service.resolve_logout_redirect(
                db,
                id_token_hint=id_token_hint,
                client_id=client_id,
                post_logout_redirect_uri=post_logout_redirect_uri,
            )
        except OAuthError as exc:
            return _error_response(exc)
        target = add_query_params(redirect_uri, {"state": state})

    response: Response
    if target:
        response = RedirectResponse(target, status_code=302)
    else:
        response = JSONResponse({"status": "logged_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
