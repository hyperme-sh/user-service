"""Explicit scoped APIs; role/organization headers never confer authority."""
import hmac
import os
import uuid
from dataclasses import asdict
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, ConfigDict
from auth_service.schemas import AuthMeResponse
from auth_service.deps import get_access_token_claims
from user_service.deps import get_current_user, require_matched_tenant
from api.infrastructure.persistence.db_session import get_db_session
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from user_service.scope_authority import network_admin, organization_member, member_record

async def ready(db: AsyncSession=Depends(get_db_session)):
    generation=os.environ.get('USER_SCOPE_GENERATION','')
    if not generation:raise HTTPException(503,'Configured scope generation is not active')
    installed=await db.scalar(text("SELECT to_regclass(current_schema() || '.identity_scope_generation')"))
    if installed is None:raise HTTPException(503,'Scope generation schema is not installed')
    version=await db.scalar(text("SELECT to_regclass(current_schema() || '.identity_scope_schema')"))
    if version is None:raise HTTPException(503,'Scope schema identity is not installed')
    from user_service.scope_schema import DDL_SHA256
    revisions=(await db.execute(text('SELECT revision,sha256 FROM identity_scope_schema'))).all()
    if revisions != [('0002_scope_authority',DDL_SHA256)]:raise HTTPException(503,'Scope schema identity differs')
    rows=(await db.execute(text('SELECT generation FROM identity_scope_generation'))).scalars().all()
    if rows != [generation]:raise HTTPException(503,'Scope generation is not installed')


async def legacy_scope_guard(request: Request):
    if os.environ.get('USER_SCOPE_GENERATION') or getattr(request.app.state,'scope_generation',None):
        raise HTTPException(403,'Use the explicit network or organization scope API')


async def scope_claims(request: Request, claims: dict=Depends(get_access_token_claims), db: AsyncSession=Depends(get_db_session)):
    organization=request.path_params.get('organization_id')
    if organization is None:return
    row=(await db.execute(text('SELECT generation,manifest_sha256 FROM identity_scope_generation'))).mappings().one()
    if (claims.get('scope_version')!=1 or claims.get('spanopticon_auth')!='tenant_session'
            or claims.get('organization_id')!=str(organization)
            or claims.get('scope_generation')!=row['generation']
            or claims.get('scope_manifest_sha256')!=row['manifest_sha256']
            or not isinstance(claims.get('network_id'),str)):
        raise HTTPException(403,'Signed current organization scope required')
    db.info['verified_scope_network']=claims['network_id']


router=APIRouter(dependencies=[Depends(ready)])


class MemberBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    role: Literal['admin','member']='member'
    can_purchase: bool=False
    active: bool=True


class AuthorityBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    subject: str
    tenant_id: uuid.UUID
    organization_id: uuid.UUID
    capability: Literal['member','manage-members','purchase']='member'


@router.get('/networks/{network_id}/authority')
async def network_authority(network_id: str, me: AuthMeResponse=Depends(get_current_user), db: AsyncSession=Depends(get_db_session)):
    grant=await network_admin(db,me.sub,network_id)
    if grant is None:raise HTTPException(403,'Current network authority required')
    return asdict(grant)


async def admin(db,me,tenant_id,organization_id):
    grant=await organization_member(db,me.sub,tenant_id,organization_id,'manage-members')
    if grant is None or grant.network_id!=db.info.get('verified_scope_network'):
        raise HTTPException(403,'Current organization administration required')
    return grant


@router.get('/organizations/{organization_id}/members', dependencies=[Depends(scope_claims)])
async def members(organization_id: uuid.UUID, limit: int=Query(50,ge=1,le=500),offset: int=Query(0,ge=0), tenant_id: uuid.UUID=Depends(require_matched_tenant), me: AuthMeResponse=Depends(get_current_user), db: AsyncSession=Depends(get_db_session)):
    await admin(db,me,tenant_id,organization_id)
    return [dict(r) for r in (await db.execute(text('SELECT user_id,role,can_purchase,active FROM identity_org_memberships WHERE tenant_id=:tenant AND organization_id=:org ORDER BY user_id LIMIT :limit OFFSET :offset'),{'tenant':tenant_id,'org':organization_id,'limit':limit,'offset':offset})).mappings()]


@router.put('/organizations/{organization_id}/members/{user_id}', dependencies=[Depends(scope_claims)])
async def put_member(organization_id: uuid.UUID,user_id: uuid.UUID,body: MemberBody,tenant_id: uuid.UUID=Depends(require_matched_tenant),me: AuthMeResponse=Depends(get_current_user),db: AsyncSession=Depends(get_db_session)):
    await admin(db,me,tenant_id,organization_id)
    target=await db.scalar(text('SELECT id FROM users WHERE id=:user AND tenant_id=:tenant AND is_active AND deleted_at IS NULL'),{'user':user_id,'tenant':tenant_id})
    if target is None:raise HTTPException(403,'Active same-tenant identity required')
    await db.execute(text('''INSERT INTO identity_org_memberships(tenant_id,organization_id,user_id,role,can_purchase,active)
        VALUES(:tenant,:org,:user,:role,:billing,:active) ON CONFLICT(organization_id,user_id)
        DO UPDATE SET role=EXCLUDED.role,can_purchase=EXCLUDED.can_purchase,active=EXCLUDED.active'''),{'tenant':tenant_id,'org':organization_id,'user':user_id,'role':body.role,'billing':body.can_purchase,'active':body.active})
    return dict(await member_record(db,tenant_id,organization_id,user_id))


@router.delete('/organizations/{organization_id}/members/{user_id}',status_code=204, dependencies=[Depends(scope_claims)])
async def delete_member(organization_id: uuid.UUID,user_id: uuid.UUID,tenant_id: uuid.UUID=Depends(require_matched_tenant),me: AuthMeResponse=Depends(get_current_user),db: AsyncSession=Depends(get_db_session)):
    await admin(db,me,tenant_id,organization_id)
    await db.execute(text('DELETE FROM identity_org_memberships WHERE tenant_id=:tenant AND organization_id=:org AND user_id=:user'),{'tenant':tenant_id,'org':organization_id,'user':user_id})


@router.post('/internal/organization-authority/check')
async def check(body: AuthorityBody,request: Request):
    supplied=request.headers.get('Authorization','').encode()
    callers=[name for name in ('AUTH','PAYMENT','PLANE') if (token:=os.environ.get(name+'_SCOPE_AUTHORITY_TOKEN')) and hmac.compare_digest(supplied,('Bearer '+token).encode())]
    if len(callers)!=1:raise HTTPException(401,'Unique service scope credential required')
    if body.capability=='manage-members' and callers[0]!='AUTH':raise HTTPException(403,'Service capability refused')
    if body.capability=='purchase' and callers[0] not in ('PAYMENT','PLANE'):raise HTTPException(403,'Service capability refused')
    if not body.subject.strip() or len(body.subject)>512:raise HTTPException(422,'Verified subject required')
    async with request.app.state.session_maker() as db:
        async with db.begin():
            grant=await organization_member(db,body.subject,body.tenant_id,body.organization_id,body.capability)
            return None if grant is None else asdict(grant)
