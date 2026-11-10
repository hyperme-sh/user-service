"""Purpose-authenticated, read-only current key-owner authority facts."""
from datetime import UTC, datetime
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Literal
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

from user_service.scoped_authority import active_tenant, allowed, tenant_network

router=APIRouter(prefix='/internal/key-authority')


class Query(BaseModel):
    model_config=ConfigDict(extra='forbid')
    version: Literal[1]=1
    request_id: uuid.UUID
    subject: str=Field(min_length=1,max_length=512)
    tenant_id: uuid.UUID
    network_id: str=Field(min_length=1,max_length=255)
    organization_id: uuid.UUID | None=None
    scope_kind: Literal['organization','network']
    generation: str=Field(min_length=1,max_length=128)
    manifest_sha256: str=Field(pattern='^[a-f0-9]{64}$')
    operation: Literal['read','mint','manage','use']
    purpose: Literal['renter','ir','service'] | None=None
    scopes: list[str]=Field(default_factory=list,max_length=32)

    @model_validator(mode='after')
    def exact_target(self):
        if (self.scope_kind=='organization')!=(self.organization_id is not None):
            raise ValueError('Exact authority target required')
        if (self.operation=='read')!=(self.purpose is None):
            raise ValueError('Key purpose required outside inventory reads')
        if any(not s or len(s)>128 for s in self.scopes):
            raise ValueError('Bounded key scope required')
        return self


def authenticate(request: Request):
    try:
        path=os.environ.get('API_KEYS_AUTHORITY_TOKEN_FILE','')
        if not path:raise ValueError()
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o077 or info.st_uid not in (0,os.geteuid()):raise ValueError()
            with os.fdopen(fd,'r',closefd=False) as stream:secret=stream.read(65)
        finally:os.close(fd)
        if not re.fullmatch('[a-f0-9]{64}',secret):raise ValueError()
    except (OSError,UnicodeError,ValueError):
        raise HTTPException(503,'Key authority credential unavailable') from None
    if not hmac.compare_digest(request.headers.get('Authorization','').encode(),('Bearer '+secret).encode()):
        raise HTTPException(401,'API key service credential required')


@router.post('',dependencies=[Depends(authenticate)])
async def lookup(body: Query,request: Request,response: Response):
    response.headers['Cache-Control']='no-store'
    if request.headers.get('X-Tenant-ID')!=str(body.tenant_id):
        raise HTTPException(403,'Tenant differs from the key authority query')
    async with request.app.state.session_maker() as session,session.begin():
        await session.execute(text('SET TRANSACTION READ ONLY'))
        seal=(await session.execute(text('SELECT generation,manifest_sha256 FROM authority_fixture_generation'))).one_or_none()
        if seal is None or tuple(seal)!=(body.generation,body.manifest_sha256):
            raise HTTPException(403,'Current authority generation required')
        valid=(not body.subject.startswith('apikey:') and await active_tenant(session,body.tenant_id)
               and await tenant_network(session,body.tenant_id)==body.network_id)
        admin=False;decision=False
        if valid and body.scope_kind=='organization' and not body.scopes:
            target=dict(subject=body.subject,tenant=body.tenant_id,organization=body.organization_id)
            admin=await allowed(session,action='organization.admin',**target)
            if body.operation=='read' or (body.operation=='manage' and body.purpose=='renter'):
                decision=await allowed(session,action='organization.read',**target)
            elif body.purpose=='renter':
                decision=await allowed(session,action='lease.purchase',**target)
            else:decision=admin
        elif valid:
            admin=await allowed(session,subject=body.subject,action='network.admin',network=body.network_id)
            decision=admin and (body.operation=='read' or (
                body.purpose=='service' and body.scopes==['oracles:attest'] and body.network_id=='s3r.ch'))
    return {**body.model_dump(mode='json'),'allowed':bool(decision),'org_admin':bool(admin and body.scope_kind=='organization'),
            'observed_at':datetime.now(UTC).isoformat()}


@router.get('/capabilities',dependencies=[Depends(authenticate)])
async def capabilities():
    """Stable protocol metadata, independent of image/revision identities."""
    return {'api_key_authority_version':1}
