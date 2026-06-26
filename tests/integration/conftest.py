from collections.abc import AsyncGenerator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import NullPool, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base, get_db
from app.models import *  # noqa: F403
from app.models.action import Action
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.service import Service
from app.models.user_role import UserRole
from app.models.users import User
from app.routers import admin, auth

BOOTSTRAP_ACTIONS = [
    "admin", "register", "login", "verify", "logout", "refresh",
    "manage_services", "manage_roles", "manage_keys", "manage_users",
]

TEST_DB_URL = "postgresql+asyncpg://jardinero:jardinero_dev@localhost:5432/jardinero_test"

engine = create_async_engine(TEST_DB_URL, echo=False, poolclass=NullPool)
test_async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with test_async_session() as session:
        result = await session.execute(select(Service).where(Service.name == "iam"))
        if not result.scalar_one_or_none():
            svc = Service(name="iam", display_name="IAM Service", description="Identity and Access Management")
            session.add(svc)
            await session.flush()

            action_map = {}
            for name in BOOTSTRAP_ACTIONS:
                action = Action(service_id=svc.id, name=name, description=f"iam:{name}")
                session.add(action)
                action_map[name] = action
            await session.flush()

            role = Role(
                service_id=svc.id, name="super_admin",
                description="Full IAM super-admin access", is_system=True,
            )
            session.add(role)
            await session.flush()

            for action in action_map.values():
                session.add(RolePermission(role_id=role.id, action_id=action.id))
            await session.commit()

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def override_get_db() -> AsyncGenerator[AsyncSession, Any]:
    async with test_async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, Any]:
    async with test_async_session() as session:
        yield session


@pytest.fixture
def test_app():
    from fastapi import FastAPI

    _app = FastAPI(title="test-hortus-clavis")
    _app.include_router(admin.router)
    _app.include_router(auth.router)
    _app.dependency_overrides[get_db] = override_get_db

    @_app.get("/health")
    async def health():
        return {"status": "ok"}

    yield _app
    _app.dependency_overrides.clear()


@pytest.fixture
async def client(test_app) -> AsyncGenerator[AsyncClient, Any]:
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def admin_headers(client: AsyncClient, db_session: AsyncSession) -> dict[str, str]:
    await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "admin123", "name": "Admin", "last_name": "User"},
    )

    result = await db_session.execute(select(User).where(User.email == "admin@test.com"))
    user = result.scalar_one_or_none()
    result = await db_session.execute(
        select(Role).join(Service, Service.id == Role.service_id)
        .where(Service.name == "iam", Role.name == "super_admin")
    )
    role = result.scalar_one_or_none()
    if user and role:
        db_session.add(UserRole(user_id=user.id, role_id=role.id))
        await db_session.commit()

    resp = await client.post("/auth/login", json={"email": "admin@test.com", "password": "admin123"})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
