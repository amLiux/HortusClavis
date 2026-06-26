import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.action import Action
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.service import Service
from app.models.user_role import UserRole
from app.models.users import User

TENANT_ADMIN_ACTIONS = ["manage_service", "manage_roles", "manage_users"]


async def get_user_permissions(db: AsyncSession, user_id: uuid.UUID) -> dict[str, list[str]]:
    role_rows = await db.execute(
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    role_ids = [r.id for r in role_rows.scalars().all()]

    permissions: dict[str, list[str]] = {}
    if not role_ids:
        return permissions

    perm_rows = await db.execute(
        select(Action, Service)
        .join(RolePermission, RolePermission.action_id == Action.id)
        .join(Service, Service.id == Action.service_id)
        .where(RolePermission.role_id.in_(role_ids))
    )
    for action, service in perm_rows.all():
        svc_name = service.name
        permissions.setdefault(svc_name, [])
        if action.name not in permissions[svc_name]:
            permissions[svc_name].append(action.name)
    return permissions


async def check_permission(db: AsyncSession, user: User, service_id: uuid.UUID, action: str) -> None:
    svc_result = await db.execute(select(Service).where(Service.id == service_id))
    svc = svc_result.scalar_one_or_none()
    if not svc:
        raise HTTPException(404, "Service not found")

    perms = await get_user_permissions(db, user.id)

    svc_actions = perms.get(svc.name, [])
    iam_actions = perms.get("iam", [])
    if action not in svc_actions and action not in iam_actions:
        raise HTTPException(403, f"Missing permission: {svc.name}/{action}")


async def check_permission_by_role(db: AsyncSession, user: User, role_id: uuid.UUID, action: str) -> None:
    role_result = await db.execute(select(Role).where(Role.id == role_id))
    role = role_result.scalar_one_or_none()
    if not role:
        raise HTTPException(404, "Role not found")
    await check_permission(db, user, role.service_id, action)
