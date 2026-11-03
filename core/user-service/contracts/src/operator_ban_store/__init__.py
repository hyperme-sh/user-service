"""User-service-owned read-only ban predicates for trusted server callers.

Return only a boolean. Preserve caller session, RLS authority and transaction;
never commit, roll back, change roles, cache results or expose ban details.
"""
from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import DateTime, String, column, or_, select, table
from sqlalchemy.dialects.postgresql import UUID as SQLUUID
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncSession

_bans = table(
    "operator_bans",
    column("id", SQLUUID(as_uuid=True)),
    column("tenant_id", SQLUUID(as_uuid=True)),
    column("subject_kind", String(16)),
    column("subject_id", SQLUUID(as_uuid=True)),
    column("lifted_at", DateTime(timezone=True)),
)


def _predicate(tenant_id, subjects):
    matches = [(_bans.c.subject_kind == kind) & _bans.c.subject_id.in_(ids)
               for kind, ids in subjects if ids]
    if not matches:
        return None
    return select(_bans.c.id).where(_bans.c.tenant_id == tenant_id,
        _bans.c.lifted_at.is_(None), or_(*matches)).limit(1)


async def active_ban(session: AsyncSession, tenant_id: UUID, *,
                     users: Sequence[UUID] = (), groups: Sequence[UUID] = (),
                     devices: Sequence[UUID] = ()) -> bool:
    """Check active user/group/device bans scoped to the requested tenant."""
    stmt = _predicate(tenant_id, (("user", users), ("group", groups), ("device", devices)))
    return False if stmt is None else bool(await session.scalar(stmt))


def subject_banned_sync(connection: Connection, tenant_id: UUID,
                        subject_kind: str, subject_id: UUID) -> bool:
    """Use the caller's connection and tenant GUC for a single ban guard."""
    stmt = _predicate(tenant_id, ((subject_kind, (subject_id,)),))
    return connection.execute(stmt).first() is not None
