from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.action import Action
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.service import Service
from app.models.user_role import UserRole
from app.models.users import User
from app.utils.logger import get_logger
from app.utils.permissions import TENANT_ADMIN_ACTIONS
from app.utils.security import hash_password

logger = get_logger(__name__)

BOOTSTRAP_SERVICE = "iam"
BOOTSTRAP_ACTIONS = [
    "admin",
    "register",
    "login",
    "verify",
    "logout",
    "refresh",
    "manage_services",
    "manage_roles",
    "manage_keys",
    "manage_users",
]
BOOTSTRAP_ROLE = "super_admin"


async def bootstrap(db: AsyncSession) -> None:
    result = await db.execute(select(Service).where(Service.name == BOOTSTRAP_SERVICE))
    existing = result.scalar_one_or_none()
    if existing:
        logger.info("bootstrap_already_seeded", extra={"props": {"service": BOOTSTRAP_SERVICE}})
        await _bootstrap_admin(db)
        await _migrate_tenant_admin_actions(db)
        return

    svc = Service(name=BOOTSTRAP_SERVICE, display_name="IAM Service", description="Identity and Access Management")
    db.add(svc)
    await db.flush()
    logger.info("bootstrap_service_created", extra={"props": {"service_id": str(svc.id)}})

    action_map: dict[str, Action] = {}
    for name in BOOTSTRAP_ACTIONS:
        action = Action(service_id=svc.id, name=name, description=f"iam:{name}")
        db.add(action)
        action_map[name] = action
    await db.flush()

    role = Role(service_id=svc.id, name=BOOTSTRAP_ROLE, description="Full IAM super-admin access", is_system=True)
    db.add(role)
    await db.flush()

    for action in action_map.values():
        db.add(RolePermission(role_id=role.id, action_id=action.id))
    await db.flush()

    logger.info(
        "bootstrap_role_created",
        extra={"props": {"role": BOOTSTRAP_ROLE, "permissions": len(action_map)}},
    )

    await _bootstrap_admin(db)
    await _migrate_tenant_admin_actions(db)


async def _bootstrap_admin(db: AsyncSession) -> None:
    admin_email = settings.bootstrap_admin_email
    if not admin_email:
        return

    result = await db.execute(select(User).where(User.email == admin_email))
    if result.scalar_one_or_none():
        return

    result = await db.execute(select(Role).join(Service, Service.id == Role.service_id).where(
        Service.name == BOOTSTRAP_SERVICE, Role.name == BOOTSTRAP_ROLE
    ))
    role = result.scalar_one_or_none()
    if not role:
        logger.warning("bootstrap_admin_skipped", extra={"props": {"reason": "super_admin_role_not_found"}})
        return

    user = User(
        email=admin_email,
        password_hash=hash_password(settings.bootstrap_admin_password or "admin"),
        name="Admin",
        last_name="User",
    )
    db.add(user)
    await db.flush()

    db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.flush()

    logger.info("bootstrap_admin_created", extra={"props": {"email": admin_email}})


async def _migrate_tenant_admin_actions(db: AsyncSession) -> None:
    result = await db.execute(select(Service).where(Service.name != BOOTSTRAP_SERVICE))
    services = list(result.scalars().all())

    for svc in services:
        existing = await db.execute(
            select(Action).where(Action.service_id == svc.id, Action.name == "manage_service")
        )
        if existing.scalar_one_or_none():
            continue

        action_map: dict[str, Action] = {}
        for name in TENANT_ADMIN_ACTIONS:
            action = Action(service_id=svc.id, name=name, description=f"{svc.name}:{name}")
            db.add(action)
            action_map[name] = action
        await db.flush()

        role_result = await db.execute(
            select(Role).where(Role.service_id == svc.id, Role.name == "admin")
        )
        admin_role = role_result.scalar_one_or_none()
        if admin_role:
            for action in action_map.values():
                db.add(RolePermission(role_id=admin_role.id, action_id=action.id))
            await db.flush()
            logger.info(
                "migrate_tenant_admin_actions",
                extra={"props": {"service": svc.name, "actions": TENANT_ADMIN_ACTIONS}},
            )
        else:
            logger.info(
                "migrate_tenant_admin_actions_no_admin_role",
                extra={"props": {"service": svc.name}},
            )
