"""Durable operator bans, audit and peers within the caller transaction.

Database-backed ban operations never use process-local books as authority.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.domain.operator.audit import OperatorAuditRow
from api.domain.operator.bans import BanError, BanRecord
from api.domain.operator.peers import PeerRecord
from user_service.models import OperatorAudit, OperatorBan, OperatorPeer


async def insert_ban(session: AsyncSession, row: BanRecord) -> None:
    try:
        async with session.begin_nested():
            session.add(
                OperatorBan(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    subject_kind=row.subject_kind,
                    subject_id=row.subject_id,
                    reason=row.reason,
                    created_by=row.created_by,
                    created_at=row.created_at,
                    lifted_at=row.lifted_at,
                    lifted_by=row.lifted_by,
                    lift_reason=row.lift_reason,
                    subject_label=row.subject_label,
                )
            )
            await session.flush()
    except IntegrityError as exc:
        if getattr(getattr(exc.orig, "diag", None), "constraint_name", None) == "uq_operator_bans_active" or "uq_operator_bans_active" in str(exc.orig):
            raise BanError("subject already has an active ban") from exc
        raise


def _ban_record(row: OperatorBan) -> BanRecord:
    return BanRecord(**{name: getattr(row, name) for name in BanRecord.__dataclass_fields__})


async def list_bans(session: AsyncSession, tenant_id: uuid.UUID, *,
                    subject_kind: str | None = None,
                    subject_id: uuid.UUID | None = None) -> list[BanRecord]:
    stmt = select(OperatorBan).where(OperatorBan.tenant_id == tenant_id)
    if subject_kind is not None:
        stmt = stmt.where(OperatorBan.subject_kind == subject_kind)
    if subject_id is not None:
        stmt = stmt.where(OperatorBan.subject_id == subject_id)
    rows = await session.scalars(stmt.order_by(OperatorBan.created_at, OperatorBan.id))
    return [_ban_record(row) for row in rows]


async def lift_ban(session: AsyncSession, tenant_id: uuid.UUID, ban_id: uuid.UUID,
                   *, lift_reason: str, lifted_by: str) -> BanRecord:
    why = lift_reason.strip()
    if not why:
        raise BanError("lift reason is required")
    row = await session.scalar(select(OperatorBan).where(
        OperatorBan.id == ban_id, OperatorBan.tenant_id == tenant_id,
        OperatorBan.lifted_at.is_(None),
    ).with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise BanError("active ban not found")
    row.lifted_at = datetime.now(UTC)
    row.lifted_by = lifted_by
    row.lift_reason = why
    await session.flush()
    return _ban_record(row)


async def insert_audit(session: AsyncSession, row: OperatorAuditRow) -> None:
    session.add(
        OperatorAudit(
            id=row.id,
            tenant_id=row.tenant_id,
            actor=row.actor,
            action=row.action,
            target_kind=row.target_kind,
            target_id=row.target_id,
            reason=row.reason,
            detail=dict(row.detail),
            created_at=row.created_at,
        )
    )
    await session.flush()


async def list_audit(
    session: AsyncSession, tenant_id: uuid.UUID, *, limit: int, offset: int
) -> list[OperatorAuditRow]:
    rows = await session.scalars(
        select(OperatorAudit)
        .where(OperatorAudit.tenant_id == tenant_id)
        .order_by(OperatorAudit.created_at.desc(), OperatorAudit.id.desc())
        .limit(limit).offset(offset)
        .execution_options(populate_existing=True)
    )
    return [OperatorAuditRow(**{
        name: getattr(row, name) for name in OperatorAuditRow.__dataclass_fields__
    }) for row in rows]


async def active_user_bans(
    session: AsyncSession, tenant_id: uuid.UUID, user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, BanRecord]:
    if not user_ids:
        return {}
    rows = await session.scalars(
        select(OperatorBan).where(
            OperatorBan.tenant_id == tenant_id,
            OperatorBan.subject_kind == "user",
            OperatorBan.subject_id.in_(user_ids),
            OperatorBan.lifted_at.is_(None),
        ).execution_options(populate_existing=True)
    )
    return {row.subject_id: _ban_record(row) for row in rows}


async def insert_peer(session: AsyncSession, row: PeerRecord) -> None:
    session.add(
        OperatorPeer(
            id=row.id,
            tenant_id=row.tenant_id,
            display_name=row.display_name,
            base_url=row.base_url,
            peer_tenant_id=row.peer_tenant_id,
            last_health_ok=row.last_health_ok,
            last_health_detail=row.last_health_detail,
            checked_at=row.checked_at,
        )
    )
    await session.flush()


async def active_ban(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    subject_kind: str,
    subject_id: uuid.UUID,
) -> OperatorBan | None:
    q = await session.execute(
        select(OperatorBan).where(
            OperatorBan.tenant_id == tenant_id,
            OperatorBan.subject_kind == subject_kind,
            OperatorBan.subject_id == subject_id,
            OperatorBan.lifted_at.is_(None),
        )
    )
    return q.scalar_one_or_none()
