"""core/user-service SQLAlchemy models; table names and schema preserved."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

from sqlalchemy.orm import Mapped, mapped_column

from controlplane_db.base import Base


import controlplane_db.models as _platform_models  # noqa: F401; register FK targets

class OperatorBan(Base):
    """Durable ban. Soft-delete, sell pause, and cert suspend are other nouns."""

    __tablename__ = "operator_bans"
    __table_args__ = (
        Index("ix_operator_bans_tenant", "tenant_id"),
        Index(
            "uq_operator_bans_active",
            "tenant_id",
            "subject_kind",
            "subject_id",
            unique=True,
            postgresql_where=text("lifted_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    subject_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lifted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lifted_by: Mapped[str | None] = mapped_column(String(512), nullable=True)
    lift_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject_label: Mapped[str | None] = mapped_column(String(512), nullable=True)


class OperatorAudit(Base):
    """Append-only operator reason log. No passwords, links, or mail secrets."""

    __tablename__ = "operator_audit"
    __table_args__ = (Index("ix_operator_audit_tenant", "tenant_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    actor: Mapped[str] = mapped_column(String(512), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OperatorPeer(Base):
    """Another spanopticon recorded on this plane. Not a chain store."""

    __tablename__ = "operator_peers"
    __table_args__ = (Index("ix_operator_peers_tenant", "tenant_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    peer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    last_health_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    last_health_detail: Mapped[str] = mapped_column(String(500), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OperatorMailQuota(Base):
    """Account-wide Mailgun month counter. Not tenant scoped. Limit is 10000."""

    __tablename__ = "operator_mail_quota"

    year_month: Mapped[str] = mapped_column(String(7), primary_key=True)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
