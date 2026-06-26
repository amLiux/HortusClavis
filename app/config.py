from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://jardinero:jardinero_dev@localhost:5432/jardinero"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "dev-secret-change-in-production!!"
    jwt_expiration: int = 7200
    debug: bool = True
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""

    model_config = {"env_prefix": "iam_", "env_file": ".env"}


settings = Settings()
