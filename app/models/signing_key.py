import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SigningKey(Base):
    """RSA key used to sign OIDC tokens.

    Keys are stored so that more than one can be active at a time, which makes
    rotation possible: publish the new key in JWKS, wait for caches to expire,
    then deactivate the old one.
    """

    __tablename__ = "signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    alg: Mapped[str] = mapped_column(String(8), nullable=False, default="RS256")
    private_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"SigningKey({self.kid}, active={self.is_active})"
