from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from panopticon_models.acl import SociACLAttributes
from panopticon_models.http_common import Page


class UserCreateBody(BaseModel):
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=255)
    last_name: str = Field(..., min_length=1, max_length=255)
    gender: str = Field(default="unspecified", max_length=64)
    is_active: bool = True


class UserUpdateBody(BaseModel):
    first_name: str | None = Field(default=None, min_length=1, max_length=255)
    last_name: str | None = Field(default=None, min_length=1, max_length=255)
    sociacl_attributes: SociACLAttributes | None = None


class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    first_name: str
    last_name: str
    gender: str
    is_active: bool
    deleted_at: datetime | None = None
    sociacl_attributes: dict | None = None

    model_config = {"from_attributes": True}


class UserListPage(Page[UserResponse]):
    """Paginated active users for the current tenant."""


class GroupCreateBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    role_id: uuid.UUID


class GroupResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str | None
    role_id: uuid.UUID

    model_config = {"from_attributes": True}


class GroupListPage(Page[GroupResponse]):
    """Paginated groups for the current tenant."""


class OrganizationCreateBody(BaseModel):
    legal_name: str = Field(..., min_length=1, max_length=512)


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    legal_name: str

    model_config = {"from_attributes": True}


class OrganizationListPage(Page[OrganizationResponse]):
    """Paginated organizations for the current tenant."""
