---
name: hc-migrate
description: >
  Expert in HortusClavis IAM — guides migration from any existing auth system,
  manages RBAC setup, understands the full codebase, and debugs integration issues.
  Covers both self-hosted (Docker/k8s) and SaaS deployments.
---

# hc-migrate — HortusClavis Migration Skill

Makes any AI agent an expert in the [HortusClavis](https://github.com/anomalyco/hortus-clavis) IAM codebase. Use it to migrate from an existing auth system, manage RBAC, debug integration issues, or just avoid reading the codebase yourself.

---

## Quick links to key source

| Concept | File |
|---|---|
| RBAC permission check | `app/utils/permissions.py:48` — `check_permission()` |
| User permissions loader | `app/utils/permissions.py:19` — `get_user_permissions()` |
| JWT creation & decode | `app/utils/security.py:17` — `create_access_token()` / `decode_access_token()` |
| Auth verify flow | `app/services/auth.py:35` — `AuthService.verify()` |
| Startup bootstrap | `app/services/bootstrap.py:32` — `bootstrap()` |
| Tenant-admin migration | `app/services/bootstrap.py:123` — `_migrate_tenant_admin_actions()` |
| Service creation (auto-seed) | `app/routers/admin.py:35` — `create_service()` |
| Role CRUD | `app/services/role.py` — `RoleService` |
| Auth endpoints | `app/routers/auth.py` — register, login, verify, logout |
| Admin endpoints | `app/routers/admin.py` — services, roles, user assignments |
| DB models | `app/models/` — Service, Action, Role, RolePermission, UserRole, User |
| Redis blacklist | `app/utils/redis.py:31` — `blacklist_token()` |

---

## Architecture reference

### Multi-tenant RBAC

```
Service (tenant)
  ├── Action (permission, e.g. "deploy", "manage_roles")
  ├── Role (e.g. "admin", "user", "editor")
  │    ├── RolePermission — links Actions to Roles
  │    └── UserRole — links Roles to Users
  └── User
```

- A **Service** is a tenant. Each service has its own actions, roles, and users.
- A **Role** is scoped to one service. `super_admin` lives in the `iam` service.
- A **User** gets permissions through `UserRole → Role → RolePermission → Action`.
- **Permission check**: a user can perform `{action}` on `{service}` if they have `iam/{action}` (global) or `{service}/{action}` (scoped). See `app/utils/permissions.py:48`.

### Auth flow

```
POST /auth/login  →  bcrypt verify  →  JWT (HS256, sub=user_id, jti, exp)
                       ↓
POST /auth/verify  →  decode JWT  →  check blacklist (Redis)  →  load user
                    →  build permissions  →  cache in Redis (SHA256 key)
                       ↓
Protected endpoint  →  get_current_user dep  →  check_permission()  →  200 | 403
```

### Bootstrap on startup

On every server start (`app/main.py:18` lifespan):
1. Seed `iam` service (if missing) — `app/services/bootstrap.py:40`
2. Create `super_admin` role with all 10 IAM actions (`app/services/bootstrap.py:52`)
3. Create admin user from env vars (`app/services/bootstrap.py:68`)
4. Migrate existing services: add `manage_service`, `manage_roles`, `manage_users` to admin role (`app/services/bootstrap.py:123`)

### Service creation auto-seed

`POST /admin/services` (needs `iam/manage_services`) at `app/routers/admin.py:35`:
1. Creates the service with user-provided actions
2. Adds 3 tenant-admin actions: `manage_service`, `manage_roles`, `manage_users`
3. Creates `admin` role with ALL actions (business + tenant-admin)
4. Creates `user` role with business actions only
5. Assigns creator as first `admin`

---

## Migration scenarios

### Auth0 → HortusClavis

| Auth0 concept | HortusClavis equivalent |
|---|---|
| Organization (org) | Service |
| Application (client) | Service (base_url) |
| Role (permission set) | Role (scoped to a service) |
| Permission (API action) | Action |
| User (with app_metadata) | User |
| Custom claims (namespace) | Actions in the user's permissions dict |
| Management API token | JWT from `/auth/login` with super_admin role |
| Rules / Actions | Not supported — handled by your business logic |

**Migration plan:**

1. **Map orgs → services**: For each Auth0 org, call `POST /admin/services` with its name and base URL. The business actions for that org become the `actions` payload.
2. **Map roles**: For each Auth0 role within an org, call `POST /admin/services/{id}/roles`. Map the permissions to action IDs from the service.
3. **Import users**: For each user, call `POST /auth/register` (set a temporary password, tell them to reset). Then `POST /admin/users/{uid}/roles` to assign their org-scoped roles.
4. **Replace JWKS verification**: Instead of verifying JWTs against Auth0's JWKS endpoint, call `POST /auth/verify` on HortusClavis (or decode + validate the secret yourself with `decode_access_token` at `app/utils/security.py:47`).
5. **Update your services**: Change the auth middleware in each microservice to point at HortusClavis's `/auth/verify` endpoint instead of Auth0's `/userinfo`.

**Script template:**

```python
import httpx, json

HC_URL = "http://localhost:8000"
TOKEN = "..."  # super_admin JWT
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

def migrate_org(auth0_org: dict):
    # 1. Create service
    svc_resp = httpx.post(f"{HC_URL}/admin/services", headers=HEADERS, json={
        "name": auth0_org["name"],
        "display_name": auth0_org["display_name"],
        "actions": [{"name": a["name"]} for a in auth0_org["actions"]],
    })
    svc_id = svc_resp.json()["id"]
    actions = {a["name"]: a["id"] for a in svc_resp.json()["actions"]}

    # 2. Create roles
    for role in auth0_org["roles"]:
        perm_ids = [actions[p] for p in role["permissions"] if p in actions]
        httpx.post(f"{HC_URL}/admin/services/{svc_id}/roles", headers=HEADERS, json={
            "name": role["name"],
            "description": role.get("description", ""),
            "permission_ids": perm_ids,
        })

    # 3. Import users (password should be reset)
    for user in auth0_org["users"]:
        reg = httpx.post(f"{HC_URL}/auth/register", json={
            "email": user["email"],
            "password": "temppass123",
            "name": user.get("name", ""),
            "last_name": user.get("last_name", ""),
        })
        if reg.status_code == 201:
            user_id = reg.json()["id"]
            role_ids = [r["id"] for r in auth0_org["roles"]
                        if r["name"] in user.get("roles", [])]
            if role_ids:
                httpx.post(f"{HC_URL}/admin/users/{user_id}/roles", headers=HEADERS,
                           json={"role_ids": role_ids})
```

### Firebase Auth → HortusClavis

| Firebase concept | HortusClavis equivalent |
|---|---|
| Project | Service |
| Custom claims (map) | Role assignments |
| User (uid) | User |
| Email/password auth | `/auth/register` + `/auth/login` |

**Migration plan:**

1. **Create a service** representing your Firebase project via `POST /admin/services`.
2. **Map custom claims to roles**: Firebase custom claims like `{role: "admin", tenant: "maticuz"}` map to a role in the `maticuz` service. Pre-create the roles, then iterate users.
3. **Import users**: For each Firebase user, call `POST /auth/register`. Firebase stores hashed passwords in a proprietary format — you'll need to trigger a password reset flow rather than migrating hashes.
4. **Assign roles**: For each user, read their custom claims, resolve to role IDs, and call `POST /admin/users/{uid}/roles`.

### Custom in-house → HortusClavis

| Common pattern | HortusClavis equivalent |
|---|---|
| `users` table | `User` model (`app/models/users.py`) |
| `roles` table | `Role` model (`app/models/role.py`) — scoped to a Service |
| `user_roles` join table | `UserRole` model (`app/models/user_role.py`) |
| `permissions` table | `Action` model (`app/models/action.py`) scoped to a Service |
| `role_permissions` join | `RolePermission` model (`app/models/role_permission.py`) |
| Token / session store | JWT (`app/utils/security.py`) + Redis blacklist |
| API key auth | Not yet built — planned |

**Migration plan:**

1. Map your application domains to **Services**. Each domain is a tenant with its own permission namespace.
2. Map your role table to **Roles** per service. Where you had global roles, create them under a dedicated `control-plane` or `platform` service.
3. Map your permission table to **Actions**. Each action is scoped to its service.
4. Import users, link them to roles.
5. Replace your existing JWT or session middleware with calls to `POST /auth/verify`.

### From scratch → HortusClavis

```bash
cp .env.example .env          # configure DB, Redis, admin credentials
make deps-up                  # start PostgreSQL + Redis
make migrate                  # run Alembic migrations
make dev                      # start server — auto-seeds IAM

# Login as bootstrap admin
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@jardinbinario.com","password":"admin"}' | jq -r .access_token)

# Create your first service
curl -s -X POST http://localhost:8000/admin/services \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "myapp", "display_name": "My App", "actions": [{"name": "read"}, {"name": "write"}]}'
```

---

## Deployment modes

### Standalone / self-hosted

Run anywhere containers run:

```bash
# Quick start (dev)
make deps-up    # PG + Redis + Loki + Grafana
make dev        # FastAPI at localhost:8000

# Docker compose (full stack)
make deps-up-all   # includes the IAM app container

# Production (planned)
# Helm chart coming soon — PRs welcome
```

**Docker image**: built from `Dockerfile` — Python 3.12-slim, uv, uvicorn. Exposes port 8000.

**Requirements**: PostgreSQL 16+, Redis 7+, at least one CPU core.

### SaaS multi-tenant

HortusClavis is designed as a multi-tenant SaaS from the ground up:

- **Each service = tenant**. Tenant isolation is baked into the permission model — a user with `maticuz/manage_roles` cannot touch `iam` or any other service's roles.
- **Control plane**: The `iam` service acts as the global control plane. Only users with `iam/manage_services` can create new tenants. The `iam/super_admin` role spans all services for emergency access.
- **Self-service**: Once a service is created, its `admin` role automatically has `manage_service`, `manage_roles`, and `manage_users` — tenant admins manage their own space without involving the platform team.
- **Scaling**: Stateless app (all state in PG + Redis) — scale horizontally behind a load balancer. No sticky sessions needed.

**Planned for SaaS offering:**
- Rate limiting per tenant (via Redis)
- Usage tracking per service (action audit log)
- Billing tier integration
- Admin dashboard UI

---

## Operation cheatsheet

All these assume a valid JWT with sufficient permissions.

```bash
# Create a tenant service (needs iam/manage_services)
curl -X POST http://localhost:8000/admin/services \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "myapp", "display_name": "My App", "actions": [{"name": "read"}, {"name": "write"}]}'

# List services
curl http://localhost:8000/admin/services \
  -H "Authorization: Bearer $TOKEN"

# Create a role (needs {svc}/manage_roles)
# Get action IDs first from the service response
curl -X POST http://localhost:8000/admin/services/{svc_id}/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "editor", "permission_ids": ["<action-uuid>"]}'

# Assign roles to a user (needs {svc}/manage_users)
curl -X POST http://localhost:8000/admin/users/{user_id}/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role_ids": ["<role-uuid>"]}'

# Verify a JWT (no special permission — any valid token works)
curl -X POST http://localhost:8000/auth/verify \
  -H "Authorization: Bearer $TOKEN"

# Check a user's permissions
curl -X POST http://localhost:8000/auth/verify \
  -H "Authorization: Bearer $TOKEN" | jq .permissions

# Get a user's current roles (needs manage_users on their service)
curl http://localhost:8000/admin/users/{user_id}/roles \
  -H "Authorization: Bearer $TOKEN"

# Remove a role assignment
curl -X DELETE http://localhost:8000/admin/users/{user_id}/roles/{role_id} \
  -H "Authorization: Bearer $TOKEN"
```

---

## Debug patterns

### 401 Unauthorized (vs 403 Forbidden)

- **401**: token missing, expired, malformed, or blacklisted. Check `app/utils/security.py:47` — `decode_access_token()` raises on invalid signature, expired `exp`, or wrong `iss`.
- **403**: token valid but user doesn't have the required permission for that action+service. Check `app/utils/permissions.py:48` — `check_permission()` raises if none of the user's permission sets contains the action.

**Quick diagnosis:**
```bash
# 1. Is the token valid at all?
curl -X POST http://localhost:8000/auth/verify -H "Authorization: Bearer $TOKEN"

# If 200, inspect permissions:
curl -s -X POST http://localhost:8000/auth/verify \
  -H "Authorization: Bearer $TOKEN" | jq .permissions

# If the expected action isn't in the permissions dict, the role assignment is missing.
```

### "JWT secret too short" warning

HortusClavis uses HS256. The secret must be at least 32 characters. Set `IAM_JWT_SECRET` in `.env` to a longer value. See `app/config.py:10`.

### Redis blacklist issues

If a logout doesn't seem to take effect, check Redis:
```bash
redis-cli KEYS "jti:*"
redis-cli TTL "jti:<the-jti>"
```

The blacklist is in `app/utils/redis.py:31` — `blacklist_token()` sets the `jti` key with TTL matching the token's remaining lifetime.

### Bootstrap already seeded

```json
{"message": "bootstrap_already_seeded", "service": "iam"}
```

This is normal on restarts. The bootstrap is idempotent — it only seeds if `iam` service does not exist. On subsequent starts it runs `_bootstrap_admin` (creates admin user if missing) and `_migrate_tenant_admin_actions` (patches existing services).

### Relation "services" does not exist

Migrations haven't run. Execute `make migrate` or `alembic upgrade head`. See `alembic/versions/` for available migrations.

### "Missing permission" on a service that exists

The user has a role but that role doesn't include the required action. Check:
1. What actions exist on the service: `GET /admin/services/{id}` (no auth needed)
2. What roles the user has: `GET /admin/users/{uid}/roles` (needs `manage_users`)
3. What actions each role grants: query `role_permissions` table joined to `actions`
4. The `check_permission` function at `app/utils/permissions.py:48` requires the action to be in `permissions[svc_name]` OR `permissions["iam"]`.

### verify returns 401 but JWT looks valid

Check Redis connectivity — the verify endpoint caches responses in Redis. If Redis is down, `cache_verify()` at `app/utils/redis.py:53` may fail silently. Check logs for `redis_connected` / `redis_disconnected`.

---

## Common workflows

### "I want to add a new tenant"

```bash
# You need iam/manage_services, so use a super_admin token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -d '{"email":"admin@jardinbinario.com","password":"admin"}' | jq -r .access_token)

curl -X POST http://localhost:8000/admin/services \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "acme-corp",
    "display_name": "Acme Corp",
    "base_url": "https://acme.example.com",
    "actions": [
      {"name": "manage_projects"},
      {"name": "view_reports"},
      {"name": "invite_users"}
    ]
  }'
```

This auto-creates `admin` and `user` roles plus tenant-admin actions. You are assigned as admin. Now you can invite others.

### "I want to onboard a client to the SaaS"

1. Create their tenant service (as above).
2. The admin role is auto-assigned to you. Optionally remove yourself and assign their admin.
3. Register their admin user: `POST /auth/register`.
4. Assign the `admin` role: `POST /admin/users/{uid}/roles`.
5. The client's admin now manages their own roles and users. They never see other tenants.

### "I want to add a custom action to an existing service"

Actions are seeded at service creation. To add new actions later:

```python
from app.database import async_session
from app.models.action import Action
from app.models.role import Role
from app.models.role_permission import RolePermission
from sqlalchemy import select
import asyncio

async def add_action(service_id, name, roles=None):
    async with async_session() as db:
        action = Action(service_id=service_id, name=name, description="")
        db.add(action)
        await db.flush()
        if roles:
            for role_name in roles:
                r = await db.execute(
                    select(Role).where(Role.service_id == service_id, Role.name == role_name)
                )
                role = r.scalar_one_or_none()
                if role:
                    db.add(RolePermission(role_id=role.id, action_id=action.id))
        await db.commit()

asyncio.run(add_action(SERVICE_ID_UUID, "deploy", roles=["admin"]))
```

### "How do microservices authenticate?"

Each microservice calls `POST /auth/verify` with the user's JWT to validate and get permissions. The response includes:

```json
{
  "authenticated": true,
  "user": {"id": "...", "email": "...", "name": "...", "last_name": "..."},
  "permissions": {
    "maticuz": ["manage_workflows", "view_dashboard"]
  },
  "expires_at": "2026-06-27T06:00:00+00:00"
}
```

The microservice checks `permissions[service_name]` for the required action. No direct DB access needed.

For machine-to-machine auth (service accounts, CI/CD), create a dedicated user with the minimum required roles and use its JWT. API key auth is planned.

---

## Testing

```bash
# All tests
make test

# Unit only (no DB)
pytest tests/unit/ -v

# Integration only (needs PG + Redis running)
pytest tests/integration/ -v

# Integration tests:
#   conftest.py creates a fresh test DB, seeds IAM + super_admin
#   admin_headers fixture registers a user with super_admin role
#   Each test is isolated (drop_all after yield)
```

---

## Architecture diagrams

### Request lifecycle

```
Request → log_requests middleware → route handler
  → [get_current_user] → decode JWT → load user → check active
  → [check_permission] → get_user_permissions → {svc: [actions]}
  → iam/{action}? → {svc}/{action}? → 200 | 403
  → business logic → DB commit → response
```

### Bootstrap sequence

```
Server start (lifespan)
  → init_redis()
  → open DB session
  → bootstrap():
      → seed iam service + 10 bootstrap actions
      → create super_admin role (all iam actions)
      → create admin user from env (if configured)
      → migrate existing services (add tenant-admin actions)
  → commit
  → Server listening
```
