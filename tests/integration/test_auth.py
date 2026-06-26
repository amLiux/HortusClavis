import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register(client: AsyncClient):
    resp = await client.post(
        "/auth/register",
        json={"email": "alice@test.com", "password": "secret123", "name": "Alice", "last_name": "Smith"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "alice@test.com"
    assert data["name"] == "Alice"
    assert "id" in data
    assert "password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    payload = {"email": "dup@test.com", "password": "secret123", "name": "Dup", "last_name": "User"}
    await client.post("/auth/register", json=payload)
    resp = await client.post("/auth/register", json=payload)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "bob@test.com", "password": "pass456", "name": "Bob", "last_name": "Jones"},
    )
    resp = await client.post("/auth/login", json={"email": "bob@test.com", "password": "pass456"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "carol@test.com", "password": "pass789", "name": "Carol", "last_name": "Brown"},
    )
    resp = await client.post("/auth/login", json={"email": "carol@test.com", "password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient):
    resp = await client.post("/auth/login", json={"email": "nobody@test.com", "password": "anything"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_verify_valid_token(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "verify@test.com", "password": "testpass", "name": "Test", "last_name": "User"},
    )
    login_resp = await client.post("/auth/login", json={"email": "verify@test.com", "password": "testpass"})
    token = login_resp.json()["access_token"]

    resp = await client.post("/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["authenticated"] is True
    assert data["auth_type"] == "user"
    assert data["user"]["email"] == "verify@test.com"
    assert isinstance(data["permissions"], dict)


@pytest.mark.asyncio
async def test_verify_invalid_token(client: AsyncClient):
    resp = await client.post("/auth/verify", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_verify_no_token(client: AsyncClient):
    resp = await client.post("/auth/verify")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={"email": "logout@test.com", "password": "logoutpass", "name": "Logout", "last_name": "Test"},
    )
    login_resp = await client.post("/auth/login", json={"email": "logout@test.com", "password": "logoutpass"})
    token = login_resp.json()["access_token"]

    resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204

    resp = await client.post("/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
