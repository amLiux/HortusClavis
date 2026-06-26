import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.action import Action
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.service import Service
from app.models.user_role import UserRole
from app.models.users import User
from app.schemas.admin import (
    RoleAssignmentInput,
    RoleInput,
    RoleResponse,
    ServiceInput,
    ServiceResponse,
    UserRoleResponse,
)
from app.services.role import RoleService
from app.utils.dependencies import get_current_user
from app.utils.permissions import TENANT_ADMIN_ACTIONS, check_permission, check_permission_by_role
from app.utils.permissions import get_user_permissions

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/services", response_model=list[ServiceResponse])
async def list_services(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Service).options(selectinload(Service.actions)).order_by(Service.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/services", response_model=ServiceResponse, status_code=201)
async def create_service(
    input: ServiceInput,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission(db, user, (await _get_iam_service(db)).id, "manage_services")

    duplicate = await db.execute(select(Service).where(Service.name == input.name))
    if duplicate.scalar_one_or_none():
        raise HTTPException(409, f"Service '{input.name}' already exists")

    svc = Service(
        name=input.name,
        display_name=input.display_name,
        description=input.description,
        base_url=input.base_url,
    )
    db.add(svc)
    await db.flush()

    action_map: dict[str, Action] = {}
    for a in input.actions:
        action = Action(service_id=svc.id, name=a.name, description=a.description)
        db.add(action)
        action_map[a.name] = action
    for tn in TENANT_ADMIN_ACTIONS:
        action = Action(service_id=svc.id, name=tn, description=f"{input.name}:{tn}")
        db.add(action)
        action_map[tn] = action
    await db.flush()

    admin_role = Role(service_id=svc.id, name="admin", description=f"Admin of {input.name}")
    user_role = Role(service_id=svc.id, name="user", description=f"User of {input.name}")
    db.add_all([admin_role, user_role])
    await db.flush()

    for action in action_map.values():
        db.add(RolePermission(role_id=admin_role.id, action_id=action.id))
    for name, action in action_map.items():
        if name not in TENANT_ADMIN_ACTIONS:
            db.add(RolePermission(role_id=user_role.id, action_id=action.id))
    await db.flush()

    db.add(UserRole(user_id=user.id, role_id=admin_role.id))
    await db.flush()

    await db.refresh(svc, ["actions"])
    return svc


@router.put("/services/{service_id}", response_model=ServiceResponse)
async def update_service(
    service_id: uuid.UUID,
    input: ServiceInput,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission(db, user, service_id, "manage_service")

    result = await db.execute(select(Service).where(Service.id == service_id))
    svc = result.scalar_one_or_none()
    if not svc:
        raise HTTPException(404, "Service not found")

    svc.display_name = input.display_name
    svc.description = input.description
    svc.base_url = input.base_url
    await db.flush()
    await db.refresh(svc)
    return svc


@router.delete("/services/{service_id}", status_code=204)
async def delete_service(
    service_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission(db, user, service_id, "manage_service")

    result = await db.execute(select(Service).where(Service.id == service_id))
    svc = result.scalar_one_or_none()
    if not svc:
        raise HTTPException(404, "Service not found")
    await db.delete(svc)


@router.post("/services/{service_id}/roles", response_model=RoleResponse, status_code=201)
async def create_role(
    service_id: uuid.UUID,
    input: RoleInput,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission(db, user, service_id, "manage_roles")
    svc = RoleService(db)
    role = await svc.create_role(
        service_id=service_id,
        name=input.name,
        description=input.description,
        permission_ids=input.permission_ids,
    )
    return role


@router.get("/services/{service_id}/roles", response_model=list[RoleResponse])
async def list_roles(
    service_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission(db, user, service_id, "manage_roles")
    svc = RoleService(db)
    return await svc.list_roles(service_id)


@router.put("/services/{service_id}/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: uuid.UUID,
    input: RoleInput,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission_by_role(db, user, role_id, "manage_roles")
    svc = RoleService(db)
    if input.permission_ids is not None:
        await svc.set_role_permissions(role_id, input.permission_ids)
    return await svc.update_role(role_id, name=input.name, description=input.description)


@router.delete("/services/{service_id}/roles/{role_id}", status_code=204)
async def delete_role(
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission_by_role(db, user, role_id, "manage_roles")
    svc = RoleService(db)
    await svc.delete_role(role_id)


@router.post("/users/{user_id}/roles", response_model=list[UserRoleResponse])
async def assign_user_roles(
    user_id: uuid.UUID,
    input: RoleAssignmentInput,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    for rid in input.role_ids:
        await check_permission_by_role(db, user, rid, "manage_users")
    svc = RoleService(db)
    await svc.assign_roles_to_user(user_id, input.role_ids)
    return await svc.get_user_roles(user_id)


@router.get("/users/{user_id}/roles", response_model=list[UserRoleResponse])
async def get_user_roles(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    target_user_roles = await RoleService(db).get_user_roles(user_id)
    for ur in target_user_roles:
        role_result = await db.execute(select(Role).where(Role.id == ur["role_id"]))
        role = role_result.scalar_one_or_none()
        if role:
            try:
                await check_permission(db, user, role.service_id, "manage_users")
            except HTTPException:
                pass
            else:
                return target_user_roles
    raise HTTPException(403, "Missing permission: manage_users on any of the user's services")


@router.delete("/users/{user_id}/roles/{role_id}", status_code=204)
async def remove_user_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    await check_permission_by_role(db, user, role_id, "manage_users")
    svc = RoleService(db)
    await svc.remove_user_role(user_id, role_id)


async def _get_iam_service(db: AsyncSession) -> Service:
    result = await db.execute(select(Service).where(Service.name == "iam"))
    svc = result.scalar_one_or_none()
    if not svc:
        raise HTTPException(500, "IAM service not found — run bootstrap first")
    return svc
