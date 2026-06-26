import uuid

import pytest

from app.utils.security import create_access_token, decode_access_token, hash_password, verify_password


class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "my_secure_password"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_same_password_different_hashes(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # bcrypt salts


class TestJWT:
    def test_create_and_decode(self):
        user_id = uuid.uuid4()
        email = "test@example.com"
        token, expires_in = create_access_token(user_id, email)

        assert isinstance(token, str)
        assert token.count(".") == 2  # JWT format
        assert expires_in > 0

        payload = decode_access_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["email"] == email
        assert payload["iss"] == "hortus-clavis"
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    def test_decode_invalid_token(self):
        with pytest.raises(Exception):
            decode_access_token("not.a.valid.jwt")

    def test_decode_wrong_secret(self):
        user_id = uuid.uuid4()
        token, _ = create_access_token(user_id, "test@test.com")
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + ".invalidsig"
        with pytest.raises(Exception):
            decode_access_token(tampered)

    def test_unique_jti(self):
        id1 = uuid.uuid4()
        id2 = uuid.uuid4()
        t1, _ = create_access_token(id1, "a@test.com")
        t2, _ = create_access_token(id2, "b@test.com")
        p1 = decode_access_token(t1)
        p2 = decode_access_token(t2)
        assert p1["jti"] != p2["jti"]

    def test_email_in_token(self):
        user_id = uuid.uuid4()
        token, _ = create_access_token(user_id, "alice@example.com")
        payload = decode_access_token(token)
        assert payload["email"] == "alice@example.com"
