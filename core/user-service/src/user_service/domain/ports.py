from __future__ import annotations

import uuid
from typing import Protocol

from controlplane_db.models import Group, Organization, Role, User, UserGroupMembership

from user_service.domain.dtos import UserCreateBody, UserUpdateBody


class UserRepositoryPort(Protocol):
    async def create(self, tenant_id: uuid.UUID, body: UserCreateBody) -> User: ...
    async def list_active(self, tenant_id: uuid.UUID) -> list[User]: ...
    async def get(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> User | None: ...
    async def update(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, body: UserUpdateBody
    ) -> User | None: ...
    async def set_role(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, role_id: uuid.UUID | None
    ) -> User | None: ...
    async def soft_delete(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> bool: ...


class RoleRepositoryPort(Protocol):
    async def get(self, tenant_id: uuid.UUID, role_id: uuid.UUID) -> Role | None: ...


class GroupRepositoryPort(Protocol):
    async def create(
        self, tenant_id: uuid.UUID, name: str, description: str | None, role_id: uuid.UUID
    ) -> Group: ...
    async def get(self, tenant_id: uuid.UUID, group_id: uuid.UUID) -> Group | None: ...
    async def list_paged(
        self,
        tenant_id: uuid.UUID,
        *,
        offset: int,
        limit: int,
        q: str | None,
    ) -> tuple[list[Group], int]: ...


class OrganizationRepositoryPort(Protocol):
    async def create(self, tenant_id: uuid.UUID, legal_name: str) -> Organization: ...
    async def get(
        self, tenant_id: uuid.UUID, organization_id: uuid.UUID
    ) -> Organization | None: ...
    async def list_paged(
        self,
        tenant_id: uuid.UUID,
        *,
        offset: int,
        limit: int,
        q: str | None,
    ) -> tuple[list[Organization], int]: ...


class MembershipRepositoryPort(Protocol):
    async def add(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, group_id: uuid.UUID
    ) -> UserGroupMembership: ...
    async def exists(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, group_id: uuid.UUID
    ) -> bool: ...
    async def remove(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, group_id: uuid.UUID
    ) -> bool: ...
