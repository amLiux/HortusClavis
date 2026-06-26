# Hortus Clavis

**The Garden of Keys** — a multi-tenant Identity & Access Management service.

Hortus Clavis is an open-source IAM (Identity & Access Management) system designed for the **Jardin Binario** ecosystem. It provides authentication, authorization, and role-based access control across multiple services, each operating as an isolated tenant with its own roles, permissions, and user assignments.

---

## Vision

A **lightweight, self-sovereign IAM** where every microservice owns its security domain. Instead of a monolithic permission matrix, Hortus Clavis delivers:

- **Tenant-level RBAC** — every service gets its own roles and actions. A tenant admin manages their service without access to others.
- **Global super-admin** — a privileged IAM role spans all services for control-plane operations.
- **No vendor lock-in** — PostgreSQL + Redis + JWT. No proprietary protocols, no external identity providers required.
- **Observable by default** — structured JSON logging + Loki + Grafana out of the box.

---

## Architecture

### High-level topology

```mermaid
graph TB
    subgraph Clients
        API[API Clients / Microservices]
        UI[Admin UI]
    end

    subgraph "Hortus Clavis"
        HC[FastAPI App<br/>port 8000]
        PG[PostgreSQL<br/>port 5432]
        RD[Redis<br/>port 6379]
    end

    subgraph Observability
        LK[Loki<br/>port 3100]
        GF[Grafana<br/>port 3000]
        PT[Promtail]
    end

    API -->|HTTP| HC
    UI -->|HTTP| HC
    HC --> PG
    HC --> RD

    PT -->|collects logs| HC
    PT --> LK
    GF -->|queries| LK
```

### Multi-tenant RBAC model

```mermaid
erDiagram
    Service ||--o{ Action : defines
    Service ||--o{ Role : scoped_to
    Role ||--o{ RolePermission : grants
    Action ||--o{ RolePermission : referenced_by
    Role ||--o{ UserRole : assigned_to
    User ||--o{ UserRole : has

    Service {
        uuid id PK
        string name "unique, eg 'iam', 'maticuz'"
        string display_name
    }

    Action {
        uuid id PK
        uuid service_id FK
        string name "eg 'manage_roles', 'deploy'"
    }

    Role {
        uuid id PK
        uuid service_id FK
        string name "eg 'super_admin', 'admin', 'user'"
        boolean is_system
    }

    RolePermission {
        uuid role_id FK "composite PK"
        uuid action_id FK "composite PK"
    }

    UserRole {
        uuid user_id FK "composite PK"
        uuid role_id FK "composite PK"
    }

    User {
        uuid id PK
        string email "unique"
        string password_hash
    }
```

### Permission check flow

```mermaid
sequenceDiagram
    participant Client
    participant API as FastAPI
    participant DB as PostgreSQL
    participant Redis

    Client->>API: POST /auth/login {email, password}
    API->>DB: authenticate user
    DB-->>API: user + password_hash
    API->>API: verify bcrypt hash
    API->>API: create JWT (sub, email, jti, exp)
    API-->>Client: {access_token, expires_in}

    Note over Client,API: ─── later, on a protected request ───

    Client->>API: GET /admin/services/{id}/roles<br/>Authorization: Bearer <jwt>
    API->>API: decode JWT, extract user_id
    API->>DB: load user, check active
    API->>DB: get user's permissions (roles → actions)
    DB-->>API: {service: [action, ...]}
    API->>API: check action in service's actions OR in iam/*

    alt Permission granted
        API->>DB: execute business logic
        DB-->>API: result
        API-->>Client: 200 OK
    else Missing permission
        API-->>Client: 403 Forbidden
    end
```

### Request lifecycle

```mermaid
flowchart LR
    A[HTTP Request] --> B[log_requests middleware]
    B --> C{Is /health?}
    C -->|Yes| D[return OK]
    C -->|No| E{Auth required?}
    E -->|No| F[route handler]
    E -->|Yes| G[get_current_user dependency]
    G --> H[decode JWT]
    H --> I{valid?}
    I -->|No| J[401 Unauthorized]
    I -->|Yes| K[load user from DB]
    K --> L{active?}
    L -->|No| M[403 Forbidden]
    L -->|Yes| N[route handler with user]
    F --> O[check_permission<br/>&nbsp;if required]
    N --> O
    O --> P{allowed?}
    P -->|No| Q[403 Forbidden]
    P -->|Yes| R[execute logic + DB commit]
    R --> S[return response]
    Q --> S
    J --> S
    M --> S
    D --> S
    S --> T[log response]
```

### Server startup sequence

```mermaid
sequenceDiagram
    participant App as FastAPI
    participant Redis
    participant DB as PostgreSQL
    participant Cache as Verify Cache

    App->>App: lifespan startup
    App->>Redis: init_redis()
    Redis-->>App: connected
    App->>DB: async_session()
    App->>DB: bootstrap()
    DB-->>App: IAM service seeded
    DB-->>App: super_admin role created
    DB-->>App: tenant-admin migration (existing services)
    App->>App: bootstrap complete
    App-->>Cache: verify cache ready
    Note over App: Server listening on :8000
```

---

## Project structure

```
app/
├── main.py                  # FastAPI app, lifespan, middleware, /health
├── config.py                # Pydantic Settings (env-prefix: IAM_)
├── database.py              # Async SQLAlchemy engine + session
├── models/                  # SQLAlchemy ORM models
│   ├── service.py           # Service (tenant)
│   ├── action.py            # Action (permission)
│   ├── role.py              # Role
│   ├── role_permission.py   # Role ↔ Action (M:N)
│   ├── user_role.py         # User ↔ Role (M:N)
│   └── users.py             # User
├── routers/
│   ├── auth.py              # /auth/* endpoints
│   └── admin.py             # /admin/* endpoints
├── schemas/
│   ├── auth.py              # Pydantic models for auth
│   └── admin.py             # Pydantic models for admin
├── services/
│   ├── auth.py              # AuthService (login, verify, logout)
│   ├── register.py          # RegisterService (create user)
│   ├── role.py              # RoleService (CRUD roles, assignments)
│   ├── rbac.py              # RBACService (list services)
│   └── bootstrap.py         # bootstrap() — seeds IAM at startup
└── utils/
    ├── security.py          # JWT + bcrypt
    ├── redis.py             # Redis client, blacklist, verify cache
    ├── permissions.py       # Permission check helpers + TENANT_ADMIN_ACTIONS
    ├── dependencies.py      # FastAPI deps (get_current_user)
    └── logger.py            # JSON structured logging

tests/
├── unit/
│   └── test_security.py     # Password hashing, JWT unit tests
└── integration/
    ├── conftest.py           # Test DB, fixtures, bootstrap
    ├── test_auth.py          # Auth endpoint integration tests
    └── test_admin.py         # Admin endpoint integration tests

infra/
├── grafana/datasources/      # Loki datasource provisioning
└── promtail/                 # Log shipping config

alembic/                      # DB migrations
versions/
  ├── 7c908761c0f1_initial.py
  └── 8c5e2f1a3b4d_roles_and_permissions.py
```

---

## Quick start

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker + Docker Compose
- Make

### 1. Start dependencies

```bash
make deps-up
```

This starts PostgreSQL (port 5432), Redis (6379), Loki (3100), and Grafana (3000).

### 2. Configure environment

```bash
cp .env.example .env
# edit .env to set JWT secret, admin credentials, etc.
```

### 3. Run database migrations

```bash
make migrate
```

### 4. Start the server

```bash
make dev
```

The server starts at `http://localhost:8000`. On first startup, it automatically seeds the **IAM** service and creates a **super_admin** role.

### 5. Run tests

```bash
make test        # all tests
pytest tests/unit/     # unit tests only (no DB needed)
pytest tests/integration/  # integration tests (needs deps-up)
```

---

## Makefile reference

| Command | What it does |
|---|---|
| `make dev` | Start the FastAPI dev server with hot-reload (`uv run uvicorn app.main:app --reload`) |
| `make lint` | Run ruff linter (`uv run ruff check .`) |
| `make format` | Auto-format with ruff (`uv run ruff format .`) |
| `make test` | Run all tests (`uv run pytest`) |
| `make migrate` | Apply pending Alembic migrations (`uv run alembic upgrade head`) |
| `make makemigrations message="..."` | Auto-generate a new Alembic migration |
| `make deps-up` | Start PostgreSQL + Redis + Loki + Promtail + Grafana |
| `make deps-up-all` | Start all containers including the IAM app itself |
| `make deps-down` | Stop all containers (data persists) |
| `make deps-down-all` | Stop all containers and delete volumes (data wiped) |
| `make logs` | Tail logs from all Docker containers |
| `make logs-app` | Tail logs from the IAM container only |
| `make grafana` | Open Grafana in your browser |
| `make loki-ready` | Wait until Loki is accepting connections |

---

## API reference

### Authentication — `/auth`

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| POST | `/auth/register` | — | `{email, password, name, last_name, avatar?}` | `201` — `RegisterResponse` |
| POST | `/auth/login` | — | `{email, password}` | `200` — `{access_token, token_type, expires_in}` |
| POST | `/auth/verify` | Bearer | — | `200` — `{authenticated, auth_type, user, permissions, expires_at}` |
| POST | `/auth/logout` | Bearer | — | `204` — blacklists the token |

### Admin — `/admin`

| Method | Path | Required permission | Description |
|---|---|---|---|
| GET | `/admin/services` | (public) | List all services with their actions |
| POST | `/admin/services` | `iam/manage_services` | Create a service + auto-seed admin/user roles + tenant-admin actions |
| PUT | `/admin/services/{id}` | `{svc}/manage_service` | Update display name, description, base URL |
| DELETE | `/admin/services/{id}` | `{svc}/manage_service` | Delete a service (cascades) |
| POST | `/admin/services/{id}/roles` | `{svc}/manage_roles` | Create a role |
| GET | `/admin/services/{id}/roles` | `{svc}/manage_roles` | List roles |
| PUT | `/admin/services/{id}/roles/{rid}` | `{svc}/manage_roles` | Update a role |
| DELETE | `/admin/services/{id}/roles/{rid}` | `{svc}/manage_roles` | Delete a role |
| POST | `/admin/users/{uid}/roles` | `{svc}/manage_users` | Assign roles to a user |
| GET | `/admin/users/{uid}/roles` | `{svc}/manage_users` | Get user's roles |
| DELETE | `/admin/users/{uid}/roles/{rid}` | `{svc}/manage_users` | Remove a role from a user |

> **Permission model**: every request checks `iam/{action}` first (global super-admin), then `{service}/{action}` (tenant-level admin). A user with `iam/manage_roles` can manage roles on any service; a user with only `maticuz/manage_roles` is confined to the maticuz service.

---

## Configuration

All settings come from environment variables with the `IAM_` prefix, loaded from `.env`:

| Variable | Default | Description |
|---|---|---|
| `IAM_DATABASE_URL` | `postgresql+asyncpg://jardinero:jardinero_dev@localhost:5432/jardinero` | PostgreSQL connection string |
| `IAM_REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `IAM_JWT_SECRET` | `dev-secret-change-in-production!!` | JWT signing key (min 32 chars) |
| `IAM_JWT_EXPIRATION` | `7200` | Token lifetime in seconds |
| `IAM_DEBUG` | `true` | Enable SQLAlchemy echo + verbose logs |
| `IAM_BOOTSTRAP_ADMIN_EMAIL` | `""` | Auto-create this user on startup |
| `IAM_BOOTSTRAP_ADMIN_PASSWORD` | `""` | Password for the bootstrap admin |

---

## Playbook

### Bootstrap a new environment

```bash
cp .env.example .env
# edit .env — set IAM_JWT_SECRET and IAM_BOOTSTRAP_ADMIN_*
make deps-up             # start PG + Redis
make migrate             # run Alembic
make dev                 # start the server → auto-seeds IAM
```

### Create a new tenant service

```bash
# Login as super-admin
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@jardinbinario.com","password":"admin"}' | jq -r .access_token)

# Create the service + auto-seed admin/user roles + tenant-admin actions
curl -s -X POST http://localhost:8000/admin/services \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "maticuz",
    "display_name": "Maticuz Service",
    "actions": [
      {"name": "manage_workflows", "description": "Create and edit workflows"},
      {"name": "view_dashboard", "description": "View the dashboard"},
      {"name": "manage_connections", "description": "Manage API connections"},
      {"name": "manage_settings", "description": "Manage service settings"}
    ]
  }'
```

This automatically:
1. Creates the service with your business actions
2. Adds 3 tenant-admin actions: `manage_service`, `manage_roles`, `manage_users`
3. Creates an `admin` role with all actions (business + tenant-admin)
4. Creates a `user` role with business actions only
5. Assigns you (the creator) as the first `admin`

### Assign a tenant admin

```bash
# Get the tenant's admin role ID
ROLES=$(curl -s http://localhost:8000/admin/services/{service_id}/roles \
  -H "Authorization: Bearer $TOKEN")
ADMIN_ROLE_ID=$(echo $ROLES | jq -r '.[] | select(.name=="admin") | .id')

# Register the new admin user
USER=$(curl -s -X POST http://localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"tenant-admin@example.com","password":"s3cret","name":"Tenant","last_name":"Admin"}')
USER_ID=$(echo $USER | jq -r .id)

# Assign the admin role
curl -s -X POST http://localhost:8000/admin/users/$USER_ID/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"role_ids\": [\"$ADMIN_ROLE_ID\"]}"
```

### Upgrade existing services (migration)

When upgrading from a pre-tenant-admin version, the server automatically migrates existing services on startup. It adds `manage_service`, `manage_roles`, and `manage_users` actions to every existing non-IAM service and grants them to the service's `admin` role. You can verify the migration:

```bash
curl -s http://localhost:8000/admin/services/{service_id} \
  -H "Authorization: Bearer $TOKEN" | jq '.actions[].name'
```

### Create a custom role

```bash
# Get the action IDs you want to grant
ACTIONS=$(curl -s http://localhost:8000/admin/services/{service_id} \
  -H "Authorization: Bearer $TOKEN" | jq .actions)

# Create the role
curl -s -X POST http://localhost:8000/admin/services/{service_id}/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "editor",
    "description": "Can edit content",
    "permission_ids": ["<action-uuid-1>", "<action-uuid-2>"]
  }'
```

### Add a Grafana dashboard for Loki

```bash
make grafana         # opens http://localhost:3000
```

Log in with `admin`/`admin`. The Loki datasource is auto-provisioned. You can query logs with:

```
{app="iam"} |= "request"
```

### Reset the test database

```bash
# drops and recreates the test DB
psql -h localhost -U jardinero -d postgres -c "DROP DATABASE IF EXISTS jardinero_test; CREATE DATABASE jardinero_test OWNER jardinero;"
```

---

## Development

### Linting & formatting

```bash
make lint
make format
```

Pre-commit hooks are configured in `.pre-commit-config.yaml` — run `pre-commit install` to enable them.

### Adding a migration

```bash
make makemigrations message="add widget table"
alembic upgrade head    # apply it
```

### Running in Docker

```bash
make deps-up-all        # full stack: PG + Redis + app + Loki + Grafana
```

The app builds from the `Dockerfile` and runs with production settings (`IAM_DEBUG=false`).

---

## Migrating to HortusClavis

Whether you're moving from **Auth0**, **Firebase Auth**, or a **custom in-house solution** — this repo ships with an opencode skill that turns any AI assistant into a HortusClavis expert. It knows the codebase, the RBAC model, the API surface, and can walk you through the entire migration step by step.

### Grab the skill

```bash
# Copy the skill into your project's opencode skills
cp -r skills/hc-migrate /path/to/your/project/.opencode/skills/

# Or reference it directly in opencode.json:
# { "skills": ["/path/to/hortusclavis/skills/hc-migrate"] }
```

Once loaded, ask your agent:

> *"I'm migrating from Auth0 to HortusClavis, guide me"*

Or fire a specific query:

> *"/hc how do I create a tenant and assign an admin?"*

> *"/hc debug my JWT — the verify endpoint returns 401"*

### What the skill covers

- **Migration playbooks** — Auth0, Firebase, custom in-house, and from-scratch, with mapping tables and script templates
- **Architecture reference** — RBAC model, permission check chain, auth flow, bootstrap sequence — all linked to source files
- **Operation cheatsheet** — curl recipes for every common operation, with the exact permission required
- **Debug patterns** — 401 vs 403, JWT issues, Redis blacklist, bootstrap logs, missing permissions
- **Deployment modes** — standalone container vs multi-tenant SaaS, with code-level explanation of tenant isolation

### Deployment options

HortusClavis runs as a **standalone service** — grab the Docker image, deploy via Docker Compose, or run in your k8s cluster:

```bash
helm upgrade --install iam ./charts/hortus-clavis \
  --set postgresql.host=mydb.rds.amazonaws.com \
  --set postgresql.password=secret \
  --set redis.host=myredis.cache.amazonaws.com \
  --set secrets.jwtSecret="your-64-char-secret"
```

See [charts/hortus-clavis/README.md](charts/hortus-clavis/README.md) for full Helm chart reference — includes HPA, PDB, ingress with TLS, init-container migrations, and production tuning.

It's also designed as a **multi-tenant SaaS** for teams that prefer managed IAM.

---

## License

Hortus Clavis is part of the Jardin Binario ecosystem.
