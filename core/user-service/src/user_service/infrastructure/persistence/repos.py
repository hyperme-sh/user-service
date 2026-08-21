from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from controlplane_db.models import Group, Organization, Role, User, UserGroupMembership
from user_service.domain.dtos import UserCreateBody, UserUpdateBody


class SqlUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(self, tenant_id: uuid.UUID, body: UserCreateBody) -> User:
        u = User(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            email=str(body.email).lower(),
            first_name=body.first_name,
            last_name=body.last_name,
            gender=body.gender,
            is_active=body.is_active,
            activated_at=datetime.now(timezone.utc) if body.is_active else None,
        )
        self._s.add(u)
        await self._s.flush()
        await self._s.refresh(u)
        return u

    async def list_active(self, tenant_id: uuid.UUID) -> list[User]:
        q = await self._s.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.deleted_at.is_(None),
            )
        )
        return list(q.scalars().all())

    async def list_active_paged(
        self,
        tenant_id: uuid.UUID,
        *,
        offset: int,
        limit: int,
        q: str | None,
    ) -> tuple[list[User], int]:
        cond = [
            User.tenant_id == tenant_id,
            User.deleted_at.is_(None),
        ]
        if q and q.strip():
            term = f"%{q.strip()}%"
            cond.append(
                or_(
                    User.email.ilike(term),
                    User.first_name.ilike(term),
                    User.last_name.ilike(term),
                )
            )
        where_clause = and_(*cond)

        total_q = await self._s.execute(
            select(func.count()).select_from(User).where(where_clause)
        )
        total = int(total_q.scalar_one())

        rows_q = await self._s.execute(
            select(User)
            .where(where_clause)
            .order_by(User.email.asc())
            .offset(offset)
            .limit(limit)
        )
        return list(rows_q.scalars().all()), total

    async def get(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> User | None:
        q = await self._s.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                User.id == user_id,
                User.deleted_at.is_(None),
            )
        )
        return q.scalar_one_or_none()

    async def get_any(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID
    ) -> User | None:
        """Include soft-deleted (for idempotent operations)."""
        q = await self._s.execute(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        )
        return q.scalar_one_or_none()

    async def update(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, body: UserUpdateBody
    ) -> User | None:
        u = await self.get(tenant_id, user_id)
        if u is None:
            return None
        if body.first_name is not None:
            u.first_name = body.first_name
        if body.last_name is not None:
            u.last_name = body.last_name
        if body.sociacl_attributes is not None:
            u.sociacl_attributes = body.sociacl_attributes.model_dump(mode="json")
        await self._s.flush()
        await self._s.refresh(u)
        return u

    async def set_role(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, role_id: uuid.UUID | None
    ) -> User | None:
        u = await self.get(tenant_id, user_id)
        if u is None:
            return None
        u.role_id = role_id
        await self._s.flush()
        await self._s.refresh(u)
        return u

    async def soft_delete(self, tenant_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        u = await self.get(tenant_id, user_id)
        if u is None:
            return False
        u.deleted_at = datetime.now(timezone.utc)
        u.is_active = False
        await self._s.flush()
        return True


class SqlRoleRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, tenant_id: uuid.UUID, role_id: uuid.UUID) -> Role | None:
        q = await self._s.execute(
            select(Role).where(Role.tenant_id == tenant_id, Role.id == role_id)
        )
        return q.scalar_one_or_none()


class SqlGroupRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(
        self,
        tenant_id: uuid.UUID,
        name: str,
        description: str | None,
        role_id: uuid.UUID,
    ) -> Group:
        g = Group(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            name=name,
            description=description,
            role_id=role_id,
        )
        self._s.add(g)
        await self._s.flush()
        await self._s.refresh(g)
        return g

    async def get(self, tenant_id: uuid.UUID, group_id: uuid.UUID) -> Group | None:
        q = await self._s.execute(
            select(Group).where(Group.tenant_id == tenant_id, Group.id == group_id)
        )
        return q.scalar_one_or_none()

    async def list_paged(
        self,
        tenant_id: uuid.UUID,
        *,
        offset: int,
        limit: int,
        q: str | None,
    ) -> tuple[list[Group], int]:
        cond = [Group.tenant_id == tenant_id]
        if q and q.strip():
            term = f"%{q.strip()}%"
            cond.append(
                or_(
                    Group.name.ilike(term),
                    Group.description.ilike(term),
                )
            )
        where_clause = and_(*cond)

        total_q = await self._s.execute(
            select(func.count()).select_from(Group).where(where_clause)
        )
        total = int(total_q.scalar_one())

        rows_q = await self._s.execute(
            select(Group)
            .where(where_clause)
            .order_by(Group.name.asc())
            .offset(offset)
            .limit(limit)
        )
        return list(rows_q.scalars().all()), total


class SqlOrganizationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(self, tenant_id: uuid.UUID, legal_name: str) -> Organization:
        o = Organization(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            legal_name=legal_name,
        )
        self._s.add(o)
        await self._s.flush()
        await self._s.refresh(o)
        return o

    async def get(
        self, tenant_id: uuid.UUID, organization_id: uuid.UUID
    ) -> Organization | None:
        q = await self._s.execute(
            select(Organization).where(
                Organization.tenant_id == tenant_id,
                Organization.id == organization_id,
            )
        )
        return q.scalar_one_or_none()

    async def list_paged(
        self,
        tenant_id: uuid.UUID,
        *,
        offset: int,
        limit: int,
        q: str | None,
    ) -> tuple[list[Organization], int]:
        cond = [Organization.tenant_id == tenant_id]
        if q and q.strip():
            term = f"%{q.strip()}%"
            cond.append(Organization.legal_name.ilike(term))
        where_clause = and_(*cond)

        total_q = await self._s.execute(
            select(func.count()).select_from(Organization).where(where_clause)
        )
        total = int(total_q.scalar_one())

        rows_q = await self._s.execute(
            select(Organization)
            .where(where_clause)
            .order_by(Organization.legal_name.asc())
            .offset(offset)
            .limit(limit)
        )
        return list(rows_q.scalars().all()), total


class SqlMembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, group_id: uuid.UUID
    ) -> UserGroupMembership:
        m = UserGroupMembership(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            group_id=group_id,
        )
        self._s.add(m)
        await self._s.flush()
        await self._s.refresh(m)
        return m

    async def exists(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, group_id: uuid.UUID
    ) -> bool:
        q = await self._s.execute(
            select(UserGroupMembership.id).where(
                UserGroupMembership.tenant_id == tenant_id,
                UserGroupMembership.user_id == user_id,
                UserGroupMembership.group_id == group_id,
            )
        )
        return q.scalar_one_or_none() is not None
