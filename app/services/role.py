import uuid

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.service import Service
from app.models.user_role import UserRole
from app.models.users import User


class RoleService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_role(
        self, service_id: uuid.UUID, name: str, description: str | None = None, permission_ids: list[uuid.UUID] | None = None
    ) -> Role:
        svc_result = await self.db.execute(select(Service).where(Service.id == service_id))
        if not svc_result.scalar_one_or_none():
            raise HTTPException(404, "Service not found")

        duplicate = await self.db.execute(
            select(Role).where(Role.service_id == service_id, Role.name == name)
        )
        if duplicate.scalar_one_or_none():
            raise HTTPException(409, f"Role '{name}' already exists for this service")

        role = Role(service_id=service_id, name=name, description=description)
        self.db.add(role)
        await self.db.flush()

        if permission_ids:
            for aid in permission_ids:
                self.db.add(RolePermission(role_id=role.id, action_id=aid))
            await self.db.flush()

        await self.db.refresh(role)
        return role

    async def list_roles(self, service_id: uuid.UUID) -> list[Role]:
        result = await self.db.execute(
            select(Role).where(Role.service_id == service_id).order_by(Role.created_at.asc())
        )
        return list(result.scalars().all())

    async def update_role(self, role_id: uuid.UUID, name: str | None = None, description: str | None = None) -> Role:
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(404, "Role not found")
        if role.is_system:
            raise HTTPException(403, "System roles cannot be modified")
        if name is not None:
            role.name = name
        if description is not None:
            role.description = description
        await self.db.flush()
        await self.db.refresh(role)
        return role

    async def delete_role(self, role_id: uuid.UUID) -> None:
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(404, "Role not found")
        if role.is_system:
            raise HTTPException(403, "System roles cannot be deleted")
        await self.db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        await self.db.execute(delete(UserRole).where(UserRole.role_id == role_id))
        await self.db.delete(role)

    async def set_role_permissions(self, role_id: uuid.UUID, permission_ids: list[uuid.UUID]) -> Role:
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(404, "Role not found")

        await self.db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        for aid in permission_ids:
            self.db.add(RolePermission(role_id=role_id, action_id=aid))
        await self.db.flush()
        return role

    async def assign_roles_to_user(self, user_id: uuid.UUID, role_ids: list[uuid.UUID]) -> list[UserRole]:
        user_result = await self.db.execute(select(User).where(User.id == user_id))
        if not user_result.scalar_one_or_none():
            raise HTTPException(404, "User not found")

        await self.db.execute(delete(UserRole).where(UserRole.user_id == user_id))

        assignments: list[UserRole] = []
        for rid in role_ids:
            role_result = await self.db.execute(select(Role).where(Role.id == rid))
            if not role_result.scalar_one_or_none():
                raise HTTPException(404, f"Role {rid} not found")
            ur = UserRole(user_id=user_id, role_id=rid)
            self.db.add(ur)
            assignments.append(ur)
        await self.db.flush()
        return assignments

    async def get_user_roles(self, user_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(Role, Service)
            .join(Service, Service.id == Role.service_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
        return [
            {"user_id": str(user_id), "role_id": str(role.id), "role_name": role.name, "service_name": svc.name}
            for role, svc in result.all()
        ]

    async def remove_user_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
        result = await self.db.execute(
            select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        )
        ur = result.scalar_one_or_none()
        if not ur:
            raise HTTPException(404, "Assignment not found")
        await self.db.delete(ur)
