import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_services(client: AsyncClient, admin_headers: dict):
    resp = await client.get("/admin/services", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["name"] == "iam"


@pytest.mark.asyncio
async def test_create_service(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        "/admin/services",
        headers=admin_headers,
        json={
            "name": "blog",
            "display_name": "Blog Service",
            "description": "Content management",
            "actions": [
                {"name": "create", "description": "Create posts"},
                {"name": "read", "description": "Read posts"},
            ],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "blog"
    assert data["display_name"] == "Blog Service"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_service_duplicate(client: AsyncClient, admin_headers: dict):
    payload = {"name": "dup", "display_name": "Duplicate"}
    await client.post("/admin/services", headers=admin_headers, json=payload)
    resp = await client.post("/admin/services", headers=admin_headers, json=payload)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_service_requires_auth(client: AsyncClient):
    resp = await client.post("/admin/services", json={"name": "x", "display_name": "X"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_role_lifecycle(client: AsyncClient, admin_headers: dict):
    svc_resp = await client.post(
        "/admin/services",
        headers=admin_headers,
        json={
            "name": "tickets",
            "display_name": "Ticket Service",
            "actions": [
                {"name": "create"},
                {"name": "read"},
                {"name": "close"},
            ],
        },
    )
    svc_id = svc_resp.json()["id"]

    role_resp = await client.post(
        f"/admin/services/{svc_id}/roles",
        headers=admin_headers,
        json={"name": "agent", "description": "Support agent"},
    )
    assert role_resp.status_code == 201
    role_data = role_resp.json()
    assert role_data["name"] == "agent"
    assert role_data["service_id"] == svc_id

    list_resp = await client.get(f"/admin/services/{svc_id}/roles", headers=admin_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 3  # admin + user + agent

    update_resp = await client.put(
        f"/admin/services/{svc_id}/roles/{role_data['id']}",
        headers=admin_headers,
        json={"name": "senior_agent", "description": "Senior support agent"},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "senior_agent"

    del_resp = await client.delete(
        f"/admin/services/{svc_id}/roles/{role_data['id']}", headers=admin_headers
    )
    assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_user_role_assignment(client: AsyncClient, admin_headers: dict):
    user_resp = await client.post(
        "/auth/register",
        json={"email": "dev@test.com", "password": "devpass", "name": "Dev", "last_name": "Eloper"},
    )
    user_id = user_resp.json()["id"]

    svc_resp = await client.post(
        "/admin/services",
        headers=admin_headers,
        json={"name": "devops", "display_name": "DevOps", "actions": [{"name": "deploy"}]},
    )
    svc_id = svc_resp.json()["id"]
    action_id = svc_resp.json()["actions"][0]["id"]

    role_resp = await client.post(
        f"/admin/services/{svc_id}/roles",
        headers=admin_headers,
        json={"name": "deployer", "permission_ids": [action_id]},
    )
    role_id = role_resp.json()["id"]

    assign_resp = await client.post(
        f"/admin/users/{user_id}/roles",
        headers=admin_headers,
        json={"role_ids": [role_id]},
    )
    assert assign_resp.status_code == 200
    assignments = assign_resp.json()
    assert len(assignments) == 1
    assert assignments[0]["role_name"] == "deployer"
    assert assignments[0]["service_name"] == "devops"

    get_resp = await client.get(f"/admin/users/{user_id}/roles", headers=admin_headers)
    assert get_resp.status_code == 200
    assert len(get_resp.json()) == 1

    login_resp = await client.post("/auth/login", json={"email": "dev@test.com", "password": "devpass"})
    token = login_resp.json()["access_token"]
    verify_resp = await client.post("/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert verify_resp.status_code == 200
    perms = verify_resp.json()["permissions"]
    assert "devops" in perms
    assert "deploy" in perms["devops"]
