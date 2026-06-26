import uuid
from datetime import datetime

from pydantic import BaseModel


class RegisterInput(BaseModel):
    email: str
    password: str
    name: str
    last_name: str
    avatar: str | None = None


class RegisterResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str
    last_name: str
    created_at: datetime
    model_config = {"from_attributes": True}


class LoginInput(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class VerifyResponse(BaseModel):
    authenticated: bool
    auth_type: str
    user: dict
    permissions: dict[str, list[str]]
    expires_at: datetime | None = None
