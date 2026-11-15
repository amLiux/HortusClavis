"""Primitives for the OIDC provider: keys, JWKS, JWTs, PKCE and helpers."""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings

SESSION_AUDIENCE = "hc-session"
SESSION_COOKIE = "hc_session"


def now() -> datetime:
    return datetime.now(UTC)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def verify_pkce(code_verifier: str, code_challenge: str, method: str | None) -> bool:
    """Verify an RFC 7636 code verifier against the stored challenge."""
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = b64url_encode(digest)
        return hmac.compare_digest(computed, code_challenge)
    if method in (None, "plain"):
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


def _int_to_b64(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64url_encode(value.to_bytes(length, "big"))


def generate_rsa_key(bits: int | None = None) -> tuple[str, str, dict]:
    """Generate an RSA keypair. Returns (private_pem, kid, public_jwk)."""
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
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def decode_rs256(token: str, public_pem: str) -> dict:
    """Decode an RS256 token issued by this provider.

    The audience is validated by the caller, because it depends on the client
    that owns the token.
    """
    return jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        issuer=settings.oidc_issuer,
        options={"verify_aud": False},
    )


def decode_session(token: str) -> dict | None:
    """Decode a browser session cookie (HS256, own audience)."""
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
    """Append query parameters to a URL, preserving any existing ones."""
    parts = urlsplit(url)
    existing = parts.query
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{existing}&{extra}" if existing and extra else existing or extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def is_secure_url(url: str) -> bool:
    return urlsplit(url).scheme == "https"
