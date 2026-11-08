"""Read-only host identity facts, owned by User and scoped to one tenant."""
from datetime import UTC, datetime
import hmac
import os
from pathlib import Path
import re
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from sqlalchemy import select, text
from controlplane_db.models import Tenant
from controlplane_tenancy.tenant_guc import set_current_tenant_id_guc
from controlplane_tenancy.tenant_membership import get_tenant_membership_row, get_tenant_role_group_ids, get_active_tenant_role_member
from operator_ban_store import active_ban

router = APIRouter(prefix='/internal/host-authority')

class Query(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version: Literal[1] = 1
    request_id: uuid.UUID
    tenant_id: uuid.UUID
    operation: Literal['tenant-active','member','bans']
    subject: str | None = Field(default=None,max_length=512)
    users: list[uuid.UUID] = Field(default_factory=list,max_length=16)
    groups: list[uuid.UUID] = Field(default_factory=list,max_length=16)
    devices: list[uuid.UUID] = Field(default_factory=list,max_length=16)

    @model_validator(mode='after')
    def scoped(self):
        if self.operation=='member':
            if not self.subject or not self.subject.strip() or self.users or self.groups or self.devices:
                raise ValueError('Membership requires only a verified subject')
        elif self.subject is not None:
            raise ValueError('Subject is only valid for membership')
        if self.operation=='tenant-active' and (self.users or self.groups or self.devices):
            raise ValueError('Tenant status accepts no subject inventory')
        return self

class Member(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: uuid.UUID
    email: str
    is_active: StrictBool
    keycloak_sub: str
    group_ids: list[uuid.UUID]
    host_group: StrictBool

class Facts(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version: Literal[1] = 1
    request_id: uuid.UUID
    tenant_id: uuid.UUID
    operation: Literal['tenant-active','member','bans']
    observed_at: datetime
    active: StrictBool | None = None
    member: Member | None = None
    banned: StrictBool | None = None


def authenticate(request: Request):
    # This purpose key does not authorize the identity command/write router.
    path=os.environ.get('HOST_IDENTITY_OWNER_TOKEN_FILE','')
    try:expected=Path(path).read_text().strip() if path else ''
    except (OSError,UnicodeError):raise HTTPException(503,'Host authority credential unavailable') from None
    if not re.fullmatch('[a-f0-9]{64}',expected):raise HTTPException(503,'Host authority credential unavailable')
    if not hmac.compare_digest(request.headers.get('Authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Host identity service credential required')


@router.post('',response_model=Facts,dependencies=[Depends(authenticate)])
async def lookup(body: Query, request: Request, response: Response):
    response.headers['Cache-Control']='no-store'
    if request.headers.get('X-Tenant-ID')!=str(body.tenant_id):
        raise HTTPException(403,'Tenant header must match the identity query')
    result=Facts(request_id=body.request_id,tenant_id=body.tenant_id,operation=body.operation,observed_at=datetime.now(UTC))
    async with request.app.state.session_maker() as session:
        async with session.begin():
            await session.execute(text('SET TRANSACTION READ ONLY'))
            await set_current_tenant_id_guc(session,body.tenant_id)
            if body.operation=='tenant-active':
                from user_service.authority_routes import enabled
                if enabled():
                    from user_service.scoped_authority import active_tenant
                    result.active=await active_tenant(session,body.tenant_id)
                else:
                    result.active=await session.scalar(select(Tenant.is_active).where(Tenant.id==body.tenant_id))
            elif body.operation=='member':
                row=await get_tenant_membership_row(session,body.tenant_id,keycloak_sub=body.subject)
                if row is not None and row.keycloak_sub==body.subject:
                    ids=await get_tenant_role_group_ids(session,body.tenant_id,user_id=row.id,role='host')
                    host=await get_active_tenant_role_member(session,body.tenant_id,keycloak_sub=body.subject,role='host')
                    from user_service.authority_routes import enabled
                    if enabled():
                        from user_service.scoped_authority import identity_active,active_tenant
                        from user_service.identity_host_setup import authorize_host_setup
                        if not await identity_active(session,body.subject) or not await active_tenant(session,body.tenant_id):
                            return result
                        host=await authorize_host_setup(body.subject,body.tenant_id,session)
                    result.member=Member(id=row.id,email=row.email or '',is_active=bool(row.is_active),
                        keycloak_sub=row.keycloak_sub,group_ids=list(ids),host_group=host is not None)
            else:
                result.banned=await active_ban(session,body.tenant_id,users=body.users,groups=body.groups,devices=body.devices)
    return result
