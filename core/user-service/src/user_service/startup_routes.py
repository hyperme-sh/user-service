"""Startup commands accept only server configuration and service credentials."""
import hmac
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from user_service._startup_contract import load, fingerprint
from user_service.startup_identity import reconcile, bind_broker, prepare_scope, one, StartupConflict

router = APIRouter(prefix='/internal/startup')


class Command(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mapping_sha256: str = Field(pattern='^[a-f0-9]{64}$')


class BindCommand(Command):
    subject: str = Field(min_length=1,max_length=255)


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
