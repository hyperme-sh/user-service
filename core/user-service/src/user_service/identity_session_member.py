"""Current identity membership for independently verified browser session facts."""
from dataclasses import dataclass
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from controlplane_db.models import Tenant
from controlplane_tenancy.tenant_guc import set_current_tenant_id_guc
from controlplane_tenancy.tenant_membership import get_tenant_membership_row
from user_service.infrastructure.operator_store import active_ban


@dataclass(frozen=True, slots=True)
class SessionMemberGrant:
    user_id: uuid.UUID


async def authorize_session_member(subject: str, tenant_id: uuid.UUID, session: AsyncSession) -> SessionMemberGrant | None:
    await set_current_tenant_id_guc(session, tenant_id)
    tenant = await session.scalar(select(Tenant.id).where(Tenant.id == tenant_id, Tenant.is_active.is_(True)))
    if tenant is None:
        return None
    member = await get_tenant_membership_row(session, tenant_id, keycloak_sub=subject)
    if (member is None or member.keycloak_sub != subject or not member.is_active
            or member.deleted_at is not None
            or await active_ban(session, tenant_id, 'user', member.id) is not None):
        return None
    # Identity facts do not grant a portal role or host setup capability.
    return SessionMemberGrant(user_id=member.id)
