import uuid
from datetime import datetime

from pydantic import BaseModel


class ActionResponse(BaseModel):
    id: uuid.UUID
    service_id: uuid.UUID
    name: str
    description: str | None = None
    model_config = {"from_attributes": True}


class ServiceResponse(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str
    description: str | None = None
    base_url: str | None = None
    is_active: bool = True
    created_at: datetime
    updated_at: datetime
    actions: list[ActionResponse] = []
    model_config = {"from_attributes": True}


class ActionInput(BaseModel):
    name: str
    description: str | None = None


class ServiceInput(BaseModel):
    name: str
    display_name: str
    description: str | None = None
    base_url: str | None = None
    actions: list[ActionInput] = []


class RoleInput(BaseModel):
    name: str
    description: str | None = None
    permission_ids: list[uuid.UUID] = []


class RoleResponse(BaseModel):
    id: uuid.UUID
    service_id: uuid.UUID
    name: str
    description: str | None = None
    is_system: bool = False
    created_at: datetime
    model_config = {"from_attributes": True}


class RoleAssignmentInput(BaseModel):
    role_ids: list[uuid.UUID]


class UserRoleResponse(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID
    role_name: str
    service_name: str
    model_config = {"from_attributes": True}
