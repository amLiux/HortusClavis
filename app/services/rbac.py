from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.service import Service


class RBACService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_services(self) -> list[Service]:
        result = await self.db.execute(select(Service).order_by(Service.created_at.desc()))
        return list(result.scalars().all())
