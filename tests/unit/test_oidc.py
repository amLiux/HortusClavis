import base64
import hashlib

import jwt

from app.config import settings
from app.utils.oidc import (
    add_query_params,
    create_session_token,
    decode_rs256,
    decode_session,
    generate_rsa_key,
    hash_token,
    public_jwk_from_pem,
    public_pem_from_private,
    sign_rs256,
    verify_pkce,
)


def test_pkce_s256_roundtrip():
    verifier = "a" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert verify_pkce(verifier, challenge, "S256")
    assert not verify_pkce("b" * 64, challenge, "S256")


def test_pkce_rejects_unknown_method():
    assert not verify_pkce("verifier", "verifier", "S512")


def test_hash_token_is_stable_and_not_reversible():
    assert hash_token("secret") == hash_token("secret")
    assert hash_token("secret") != hash_token("secret2")
    assert len(hash_token("secret")) == 64


def test_generated_key_produces_rs256_jwt_and_jwks_entry():
    private_pem, kid, jwk = generate_rsa_key(2048)
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == kid
    assert jwk["alg"] == "RS256"
    assert "d" not in jwk  # never expose private material

    token = sign_rs256({"sub": "abc", "iss": settings.oidc_issuer}, private_pem, kid)
    assert jwt.get_unverified_header(token)["kid"] == kid
    assert decode_rs256(token, public_pem_from_private(private_pem))["sub"] == "abc"


def test_public_jwk_from_pem_matches_generated_kid():
    private_pem, kid, _jwk = generate_rsa_key(2048)
    assert public_jwk_from_pem(private_pem, kid)["kid"] == kid
    assert "<" not in private_pem  # JWK must not contain private material
    assert "BEGIN PRIVATE KEY" in private_pem  # PEM, not DER


def test_session_token_roundtrip_and_tamper_detection():
    token = create_session_token("4b1c2f3a-0000-0000-0000-000000000000")
    payload = decode_session(token)
    assert payload is not None
    assert payload["sub"] == "4b1c2f3a-0000-0000-0000-000000000000"
    assert payload["aud"] == "hc-session"
    assert decode_session(token + "x") is None
    assert decode_session("not-a-token") is None


def test_add_query_params_preserves_existing_query_and_fragment():
    url = "https://app.example.com/cb?existing=1#frag"
    result = add_query_params(url, {"code": "abc", "state": None})
    assert "existing=1" in result
    assert "code=abc" in result
    assert "state" not in result
    assert result.endswith("#frag")
