import asyncio

from alembic.command import upgrade
from alembic.config import Config as AlembicConfig

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def run_migrations() -> None:
    alembic_cfg = AlembicConfig()
    alembic_cfg.set_main_option("script_location", "alembic")
    alembic_cfg.set_main_option("sqlalchemy.url", str(settings.database_url))
    await asyncio.to_thread(upgrade, alembic_cfg, "head")
    logger.info("migrations_applied")
