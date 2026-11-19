from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://jardinero:jardinero_dev@localhost:5432/jardinero"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "dev-secret-change-in-production!!"
    jwt_expiration: int = 7200
    debug: bool = True
    # OIDC provider
    oidc_enabled: bool = True
    oidc_issuer: str = "http://localhost:8000"
    oidc_access_token_expiration: int = 900
    oidc_refresh_token_expiration: int = 2_592_000
    oidc_authorization_code_expiration: int = 300
    oidc_session_expiration: int = 3600
    oidc_signing_key_bits: int = 2048
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""

    # The same .env is read by the app and by compose: ignore keys that are not
    # part of the IAM settings (POSTGRES_*, HC_*_VOLUME, ...) instead of failing.
    model_config = SettingsConfigDict(env_prefix="iam_", env_file=".env", extra="ignore")

    def model_post_init(self, _data):
        if self.database_url.startswith("postgresql://"):
            self.database_url = self.database_url.replace(
                "postgresql://", "postgresql+asyncpg://", 1
            )
        self.oidc_issuer = self.oidc_issuer.rstrip("/")


settings = Settings()
