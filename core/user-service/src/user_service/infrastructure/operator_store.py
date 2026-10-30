"""Postgres copies of operator bans, audit, and peers.

The in-process books are what same-process doors read in tests. When a
request session exists, the same write lands in Postgres for other services.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.domain.operator.audit import OperatorAuditRow
from api.domain.operator.bans import BanRecord
from api.domain.operator.peers import PeerRecord
from user_service.models import OperatorAudit, OperatorBan, OperatorPeer


async def insert_ban(session: AsyncSession, row: BanRecord) -> None:
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


async def update_lift(session: AsyncSession, row: BanRecord) -> None:
    found = await session.get(OperatorBan, row.id)
    if found is None:
        return
    found.lifted_at = row.lifted_at
    found.lifted_by = row.lifted_by
    found.lift_reason = row.lift_reason
    await session.flush()


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
