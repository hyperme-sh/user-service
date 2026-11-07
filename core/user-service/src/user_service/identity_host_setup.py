"""Current host membership and durable user-ban authority in the user owner."""
from dataclasses import dataclass
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from controlplane_tenancy.tenant_guc import set_current_tenant_id_guc
from controlplane_tenancy.tenant_membership import get_active_tenant_role_member
from user_service.infrastructure.operator_store import active_ban


@dataclass(frozen=True, slots=True)
class HostSetupGrant:
    user_id: uuid.UUID


async def authorize_host_setup(subject: str, tenant_id: uuid.UUID, session: AsyncSession) -> HostSetupGrant | None:
    # This is the already verified dedicated issuer subject; never email, caller
    # roles or general tenant-switch/platform authority. Preserve it exactly.
    await set_current_tenant_id_guc(session, tenant_id)
    member = await get_active_tenant_role_member(session, tenant_id, keycloak_sub=subject, role='host')
    if member is None or await active_ban(session, tenant_id, 'user', member.id) is not None:
        return None
    return HostSetupGrant(user_id=member.id)
