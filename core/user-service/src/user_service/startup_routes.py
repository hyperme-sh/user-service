"""Startup commands accept only server configuration and service credentials."""
import hmac
import os
from pathlib import Path
from uuid import UUID
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from user_service._startup_contract import load, fingerprint
from user_service.startup_identity import reconcile, bind_broker, prepare_scope, one, StartupConflict
from user_service.startup_identity import startup_scope_identity
from user_service.scoped_authority import organization_member, tenant_network

router = APIRouter(prefix='/internal/startup')


class Command(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mapping_sha256: str = Field(pattern='^[a-f0-9]{64}$')


class BindCommand(Command):
    subject: str = Field(min_length=1,max_length=255)


class ScopeCommand(BindCommand):
    tenant_id: UUID
    organization_id: UUID


def authorize(request, *names):
    if os.environ.get('STARTUP_IDENTITY_ENABLED') != '1':
        raise HTTPException(503,'Startup identity is not enabled')
    supplied = request.headers.get('authorization','').encode()
    if not any(value and hmac.compare_digest(supplied, ('Bearer '+value).encode())
               for value in (os.environ.get(name,'') for name in names)):
        raise HTTPException(401,'Scoped startup service credential required')


def configuration(command):
    try:
        config = load(Path(os.environ.get('STARTUP_IDENTITY_CONFIG_FILE','')))
        if fingerprint(config) != command.mapping_sha256:
            raise ValueError('Startup configuration mapping differs')
        return config
    except (ValueError, OSError):
        raise HTTPException(409,'Startup configuration mapping unavailable or conflicting') from None


async def invoke(request, command, operation):
    config = configuration(command)
    try:
        async with request.app.state.session_maker() as db:
            async with db.begin():
                if operation == 'bind':
                    return await bind_broker(db, config, command.subject)
                if operation == 'status':
                    tenant = await prepare_scope(db, config)
                    if not await one(db,'SELECT user_id FROM startup_identity_bindings WHERE tenant_id=:tenant',{'tenant':tenant}):
                        raise StartupConflict('Startup person is not reconciled')
                return await reconcile(db, config)
    except StartupConflict as error:
        raise HTTPException(409,str(error)) from None
    except IntegrityError:
        raise HTTPException(409,'Startup identity uniqueness conflict') from None


@router.post('/reconcile')
async def reconcile_route(command: Command, request: Request):
    authorize(request, 'USER_STARTUP_TOKEN')
    return await invoke(request, command, 'reconcile')


@router.post('/status')
async def status_route(command: Command, request: Request):
    authorize(request, 'USER_STARTUP_TOKEN', 'USER_STARTUP_READ_TOKEN')
    return await invoke(request, command, 'status')


@router.post('/bind')
async def bind_route(command: BindCommand, request: Request):
    authorize(request, 'AUTH_IDENTITY_OWNER_TOKEN')
    return await invoke(request, command, 'bind')


@router.post('/scope')
async def scope_route(command: ScopeCommand, request: Request):
    authorize(request, 'USER_STARTUP_READ_TOKEN')
    config = configuration(command)
    binding = config['binding']
    organization = str(command.organization_id)
    if (binding['version'] != 2 or str(command.tenant_id) != config['owner']['tenant_id']
            or binding['oidc']['broker_subject'] != command.subject
            or organization not in {row['organization_id'] for row in binding['organizations'].values()}):
        return None
    async with request.app.state.session_maker() as db, db.begin():
        member = await organization_member(db, command.tenant_id, command.organization_id, command.subject)
        if member is None:
            return None
        identity = await startup_scope_identity(db, command.tenant_id, command.subject)
        network = await tenant_network(db, command.tenant_id)
    if identity is None or network != config['owner']['network_id']:
        return None
    user_id, generation, manifest = identity
    if (str(user_id) != command.subject or member['user_id'] != user_id or generation != 'startup-v1'
            or manifest != command.mapping_sha256):
        return None
    return dict(subject=command.subject, user_id=user_id, network_id=network,
                tenant_id=command.tenant_id, organization_id=command.organization_id,
                role=member['role'], can_purchase=member['can_purchase_leases'],
                generation=generation, manifest_sha256=manifest)
