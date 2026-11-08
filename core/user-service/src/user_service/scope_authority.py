"""Current subject-bound network and organization authority owned by User."""
from dataclasses import dataclass, asdict
import uuid
import os
from sqlalchemy import text
from controlplane_tenancy.tenant_guc import set_current_tenant_id_guc
from user_service.infrastructure.operator_store import active_ban


@dataclass(frozen=True)
class ScopeGrant:
    subject: str
    user_id: uuid.UUID
    network_id: str
    tenant_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None
    role: str = 'member'
    can_purchase: bool = False
    generation: str = ''
    manifest_sha256: str = ''


async def grant(db,*args,**kwargs):
    rows=(await db.execute(text('SELECT generation,manifest_sha256 FROM identity_scope_generation'))).mappings().all()
    if len(rows)!=1 or rows[0]['generation']!=os.environ.get('USER_SCOPE_GENERATION'):
        return None
    return ScopeGrant(*args,**kwargs,**dict(rows[0]))


async def network_admin(db, subject, network_id):
    await set_current_tenant_id_guc(db,None)
    row=(await db.execute(text("""SELECT u.id FROM identity_network_admins a
        JOIN identity_networks n ON n.id=a.network_id
        JOIN users u ON u.id=a.user_id
        WHERE n.id=:network AND n.active AND a.active AND u.is_active
        AND u.deleted_at IS NULL AND u.tenant_id IS NULL AND u.keycloak_sub=:subject"""),{'network':network_id,'subject':subject})).scalar_one_or_none()
    return None if row is None else await grant(db,subject,row,network_id,role='admin')


async def organization_member(db, subject, tenant_id, organization_id, capability='member'):
    await set_current_tenant_id_guc(db,tenant_id)
    row=(await db.execute(text("""SELECT u.id,m.role,m.can_purchase,b.network_id
        FROM identity_org_memberships m
        JOIN users u ON u.id=m.user_id AND u.tenant_id=m.tenant_id
        JOIN organizations o ON o.id=m.organization_id AND o.tenant_id=m.tenant_id
        JOIN tenants t ON t.id=m.tenant_id
        JOIN identity_network_tenants b ON b.tenant_id=t.id
        JOIN identity_networks n ON n.id=b.network_id
        WHERE m.tenant_id=:tenant AND m.organization_id=:org AND m.active
        AND u.keycloak_sub=:subject AND u.is_active AND u.deleted_at IS NULL
        AND t.is_active AND n.active FOR SHARE OF m"""),{'tenant':tenant_id,'org':organization_id,'subject':subject})).mappings().one_or_none()
    if row is None or await active_ban(db,tenant_id,'user',row['id']) is not None:
        return None
    if capability not in ('member','manage-members','purchase'):
        return None
    if capability=='manage-members' and row['role']!='admin':return None
    if capability=='purchase' and not row['can_purchase']:return None
    return await grant(db,subject,row['id'],row['network_id'],tenant_id,organization_id,row['role'],row['can_purchase'])


async def member_record(db, tenant_id, organization_id, user_id):
    return (await db.execute(text('SELECT user_id,role,can_purchase,active FROM identity_org_memberships WHERE tenant_id=:tenant AND organization_id=:org AND user_id=:user'),{'tenant':tenant_id,'org':organization_id,'user':user_id})).mappings().one_or_none()
