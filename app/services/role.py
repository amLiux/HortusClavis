import uuid

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.service import Service
from app.models.user_role import UserRole
from app.models.users import User
from app.utils.logger import get_logger

logger = get_logger(__name__)


class RoleService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_role(
        self,
        service_id: uuid.UUID,
        name: str,
        description: str | None = None,
        permission_ids: list[uuid.UUID] | None = None,
    ) -> Role:
        svc_result = await self.db.execute(select(Service).where(Service.id == service_id))
        if not svc_result.scalar_one_or_none():
            logger.warning(
                "role.create_rejected",
                extra={"props": {"reason": "service_not_found", "service_id": str(service_id)}},
            )
            raise HTTPException(404, "Service not found")

        duplicate = await self.db.execute(
            select(Role).where(Role.service_id == service_id, Role.name == name)
        )
        if duplicate.scalar_one_or_none():
            logger.warning(
                "role.create_rejected",
                extra={
                    "props": {
                        "reason": "duplicate_name",
                        "service_id": str(service_id),
                        "role_name": name,
                    }
                },
            )
            raise HTTPException(409, f"Role '{name}' already exists for this service")

        role = Role(service_id=service_id, name=name, description=description)
        self.db.add(role)
        await self.db.flush()

        if permission_ids:
            for aid in permission_ids:
                self.db.add(RolePermission(role_id=role.id, action_id=aid))
            await self.db.flush()

        await self.db.refresh(role)
        logger.info(
            "role.created",
            extra={
                "props": {
                    "role_id": str(role.id),
                    "service_id": str(service_id),
                    "role_name": role.name,
                    "permissions": len(permission_ids or []),
                }
            },
        )
        return role

    async def list_roles(self, service_id: uuid.UUID) -> list[Role]:
        result = await self.db.execute(
            select(Role).where(Role.service_id == service_id).order_by(Role.created_at.asc())
        )
        return list(result.scalars().all())

    async def update_role(
        self, role_id: uuid.UUID, name: str | None = None, description: str | None = None
    ) -> Role:
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            logger.warning(
                "role.update_rejected",
                extra={"props": {"reason": "not_found", "role_id": str(role_id)}},
            )
            raise HTTPException(404, "Role not found")
        if role.is_system:
            logger.warning(
                "role.update_rejected",
                extra={"props": {"reason": "system_role", "role_id": str(role_id)}},
            )
            raise HTTPException(403, "System roles cannot be modified")
        if name is not None:
            role.name = name
        if description is not None:
            role.description = description
        await self.db.flush()
        await self.db.refresh(role)
        logger.info(
            "role.updated",
            extra={"props": {"role_id": str(role.id), "role_name": role.name}},
        )
        return role

    async def delete_role(self, role_id: uuid.UUID) -> None:
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            logger.warning(
                "role.delete_rejected",
                extra={"props": {"reason": "not_found", "role_id": str(role_id)}},
            )
            raise HTTPException(404, "Role not found")
        if role.is_system:
            logger.warning(
                "role.delete_rejected",
                extra={"props": {"reason": "system_role", "role_id": str(role_id)}},
            )
            raise HTTPException(403, "System roles cannot be deleted")
        await self.db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        await self.db.execute(delete(UserRole).where(UserRole.role_id == role_id))
        await self.db.delete(role)
        logger.info(
            "role.deleted",
            extra={"props": {"role_id": str(role_id), "role_name": role.name}},
        )

    async def set_role_permissions(
        self, role_id: uuid.UUID, permission_ids: list[uuid.UUID]
    ) -> Role:
        result = await self.db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            logger.warning(
                "role.permissions_rejected",
                extra={"props": {"reason": "not_found", "role_id": str(role_id)}},
            )
            raise HTTPException(404, "Role not found")

        await self.db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        for aid in permission_ids:
            self.db.add(RolePermission(role_id=role_id, action_id=aid))
        await self.db.flush()
        logger.info(
            "role.permissions_set",
            extra={"props": {"role_id": str(role_id), "permissions": len(permission_ids)}},
        )
        return role

    async def assign_roles_to_user(
        self, user_id: uuid.UUID, role_ids: list[uuid.UUID]
    ) -> list[UserRole]:
        user_result = await self.db.execute(select(User).where(User.id == user_id))
        if not user_result.scalar_one_or_none():
            logger.warning(
                "role.assign_rejected",
                extra={"props": {"reason": "user_not_found", "user_id": str(user_id)}},
            )
            raise HTTPException(404, "User not found")

        await self.db.execute(delete(UserRole).where(UserRole.user_id == user_id))

        assignments: list[UserRole] = []
        for rid in role_ids:
            role_result = await self.db.execute(select(Role).where(Role.id == rid))
            if not role_result.scalar_one_or_none():
                logger.warning(
                    "role.assign_rejected",
                    extra={"props": {"reason": "role_not_found", "role_id": str(rid)}},
                )
                raise HTTPException(404, f"Role {rid} not found")
            ur = UserRole(user_id=user_id, role_id=rid)
            self.db.add(ur)
            assignments.append(ur)
        await self.db.flush()
        logger.info(
            "role.user_assignments_set",
            extra={
                "props": {
                    "user_id": str(user_id),
                    "role_ids": [str(rid) for rid in role_ids],
                }
            },
        )
        return assignments

    async def get_user_roles(self, user_id: uuid.UUID) -> list[dict]:
        result = await self.db.execute(
            select(Role, Service)
            .join(Service, Service.id == Role.service_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
        return [
            {
                "user_id": str(user_id),
                "role_id": str(role.id),
                "role_name": role.name,
                "service_name": svc.name,
            }
            for role, svc in result.all()
        ]

    async def remove_user_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
        result = await self.db.execute(
            select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        )
        ur = result.scalar_one_or_none()
        if not ur:
            logger.warning(
                "role.unassign_rejected",
                extra={
                    "props": {
                        "reason": "assignment_not_found",
                        "user_id": str(user_id),
                        "role_id": str(role_id),
                    }
                },
            )
            raise HTTPException(404, "Assignment not found")
        await self.db.delete(ur)
        logger.info(
            "role.user_assignment_removed",
            extra={"props": {"user_id": str(user_id), "role_id": str(role_id)}},
        )
