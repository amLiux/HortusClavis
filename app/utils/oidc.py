"""Pure primitives for the OIDC provider: keys, JWKS, JWTs, PKCE and parsing.

Nothing here touches the database, the network or the HTTP layer (``add_query_params``
and ``is_secure_url`` are plain URL string helpers). Anything that needs a session
to make a decision belongs in ``app.services.oidc`` instead.
"""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings

SESSION_AUDIENCE = "hc-session"
SESSION_COOKIE = "hc_session"

#: Query/form fields the authorize endpoint understands. Anything else is ignored.
AUTHORIZE_PARAMS = (
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


def now() -> datetime:
    """Current time as a timezone-aware UTC datetime (all token maths use UTC)."""
    return datetime.now(UTC)


def b64url_encode(value: bytes) -> str:
    """Base64url-encode without padding, as required by JOSE (RFC 7515)."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode base64url input, restoring the padding stripped by :func:`b64url_encode`."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_token(value: str) -> str:
    """Hash an opaque token (code, refresh token) for storage.

    Plain SHA-256 is enough here: the tokens are 256-bit random values, so they
    are not brute-forceable, and the hash has to be looked up by value.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_token(nbytes: int = 32) -> str:
    """Generate a URL-safe random token with ``nbytes`` of entropy."""
    return secrets.token_urlsafe(nbytes)


def verify_pkce(code_verifier: str, code_challenge: str, method: str | None) -> bool:
    """Verify an RFC 7636 code verifier against the stored challenge.

    Uses a constant-time comparison. ``plain`` is only honoured for legacy
    clients; the provider itself rejects it when issuing codes.
    """
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = b64url_encode(digest)
        return hmac.compare_digest(computed, code_challenge)
    if method in (None, "plain"):
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


def _int_to_b64(value: int) -> str:
    """Encode a positive integer as a minimal-length base64url string (JWK ``n``/``e``)."""
    length = (value.bit_length() + 7) // 8
    return b64url_encode(value.to_bytes(length, "big"))


def generate_rsa_key(bits: int | None = None) -> tuple[str, str, dict]:
    """Generate an RSA keypair. Returns (private_pem, kid, public_jwk).

    The ``kid`` is the RFC 7638 JWK thumbprint, so the same key always gets the
    same identifier. The private key is returned unencrypted: callers are
    expected to protect it at rest (see SECURITY.md / HC-04).
    """
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=bits or settings.oidc_signing_key_bits
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_b64(numbers.n),
        "e": _int_to_b64(numbers.e),
    }
    # RFC 7638 JWK thumbprint — stable across restarts for the same key.
    canonical = json.dumps(
        {k: jwk[k] for k in ("e", "kty", "n")}, separators=(",", ":"), sort_keys=True
    )
    kid = b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())
    jwk["kid"] = kid
    return private_pem, kid, jwk


def public_jwk_from_pem(private_pem: str, kid: str) -> dict:
    """Derive the public JWK (``n``/``e``) of a stored PEM private key.

    Used to publish ``/oidc/jwks.json`` without ever serialising the private half.
    """
    key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_b64(numbers.n),
        "e": _int_to_b64(numbers.e),
    }


def public_pem_from_private(private_pem: str) -> str:
    """Extract the PEM public key from a PEM private key (used to verify own tokens)."""
    key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def sign_rs256(payload: dict, private_pem: str, kid: str) -> str:
    """Sign a JWT with RS256 and stamp the signing key id in the header."""
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def decode_rs256(token: str, public_pem: str) -> dict:
    """Decode an RS256 token issued by this provider.

    Verifies the signature, ``iss`` and expiry. The audience is validated by the
    caller, because it depends on the client that owns the token.
    """
    return jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        issuer=settings.oidc_issuer,
        options={"verify_aud": False},
    )


def decode_session(token: str) -> dict | None:
    """Decode a browser session cookie (HS256, own audience).

    Returns ``None`` for any invalid, expired or tampered cookie instead of
    raising, so callers can treat "no session" and "bad session" the same.
    """
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            audience=SESSION_AUDIENCE,
            issuer="hortus-clavis",
        )
    except jwt.PyJWTError:
        return None


def create_session_token(user_id: str) -> str:
    """Mint the short-lived browser session cookie value for ``user_id``.

    The session is stateless (HS256 with ``settings.jwt_secret``), so it cannot
    be revoked server-side before ``exp``; logout only deletes the cookie.
    """
    issued = now()
    payload = {
        "sub": user_id,
        "iss": "hortus-clavis",
        "aud": SESSION_AUDIENCE,
        "iat": issued,
        "auth_time": int(issued.timestamp()),
        "exp": issued + timedelta(seconds=settings.oidc_session_expiration),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def add_query_params(url: str, params: dict[str, str | None]) -> str:
    """Append query parameters to a URL, preserving any existing ones.

    ``None`` values are dropped, so callers can pass optional fields (``state``)
    without branching.
    """
    parts = urlsplit(url)
    existing = parts.query
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{existing}&{extra}" if existing and extra else existing or extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def is_secure_url(url: str) -> bool:
    """True when the URL is HTTPS, used to decide the ``secure`` cookie flag."""
    return urlsplit(url).scheme == "https"


def extract_authorize_params(source) -> dict:
    """Pick the authorize fields out of ``request.query_params`` or a submitted form.

    Unknown fields are ignored and empty strings normalise to ``None``, so the
    rest of the flow only deals with ``str | None`` values.
    """
    return {key: source.get(key) or None for key in AUTHORIZE_PARAMS}


def parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    """Parse ``Authorization: Basic <client_id>:<secret>`` (RFC 6749 §2.3.1).

    Both values are form-urlencoded by that spec, hence ``unquote``. Returns
    ``None`` for missing, malformed or non-Basic headers so the caller can fall
    back to the form-encoded ``client_id``/``client_secret``.
    """
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    client_id, _, secret = raw.partition(":")
    return unquote(client_id), unquote(secret)


def extract_bearer_token(header: str | None) -> str | None:
    """Return the token of ``Authorization: Bearer <token>``, or ``None`` if absent."""
    if not header or not header.lower().startswith("bearer "):
        return None
    return header[7:].strip() or None
