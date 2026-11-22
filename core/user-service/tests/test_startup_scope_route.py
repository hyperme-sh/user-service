"""Verify that the startup reader checks the live synthetic subject and organization."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from fastapi import HTTPException

from user_service import startup_routes

TENANT = UUID('12345678-1234-4abc-8abc-123456781234')
ORG = UUID('22345678-1234-4abc-8abc-123456781234')
ACTOR = UUID('32345678-1234-4abc-8abc-123456781234')
FOREIGN = UUID('42345678-1234-4abc-8abc-123456781234')
STAMP = 'a' * 64


@pytest.mark.asyncio
async def test_scope_route_only_reads_current_synthetic_membership(monkeypatch):
    config = {
        'owner': {'tenant_id': str(TENANT), 'network_id': 'hyperme.sh'},
        'binding': {'version': 2, 'oidc': {'broker_subject': str(ACTOR)},
                    'organizations': {'nightly': {'organization_id': str(ORG)}}},
    }

    @asynccontextmanager
    async def transaction():
        yield

    @asynccontextmanager
    async def connection():
        yield db

    db = SimpleNamespace(begin=transaction)
    request = SimpleNamespace(headers={'authorization': 'Bearer test-reader'}, app=SimpleNamespace(
        state=SimpleNamespace(session_maker=connection)))
    command = startup_routes.ScopeCommand(mapping_sha256=STAMP, tenant_id=TENANT,
                                          organization_id=ORG, subject=str(ACTOR))
    monkeypatch.setenv('STARTUP_IDENTITY_ENABLED', '1')
    monkeypatch.setenv('USER_STARTUP_READ_TOKEN', 'test-reader')
    monkeypatch.setattr(startup_routes, 'configuration', Mock(return_value=config))
    membership = AsyncMock(return_value={'user_id': ACTOR, 'role': 'admin', 'can_purchase_leases': False})
    monkeypatch.setattr(startup_routes, 'organization_member', membership)
    monkeypatch.setattr(startup_routes, 'startup_scope_identity', AsyncMock(return_value=(ACTOR, 'startup-v1', STAMP)))
    monkeypatch.setattr(startup_routes, 'tenant_network', AsyncMock(return_value='hyperme.sh'))

    for field, value in [('tenant_id', FOREIGN), ('organization_id', FOREIGN), ('subject', str(FOREIGN))]:
        assert await startup_routes.scope_route(command.model_copy(update={field: value}), request) is None
    membership.assert_not_awaited()

    grant = await startup_routes.scope_route(command, request)
    assert grant == dict(subject=str(ACTOR), user_id=ACTOR, network_id='hyperme.sh', tenant_id=TENANT,
                         organization_id=ORG, role='admin', can_purchase=False, generation='startup-v1',
                         manifest_sha256=STAMP)
    membership.assert_awaited_once_with(db, TENANT, ORG, str(ACTOR))
    membership.return_value = None
    assert await startup_routes.scope_route(command, request) is None

    monkeypatch.setenv('USER_STARTUP_TOKEN', 'test-writer')
    request.headers['authorization'] = 'Bearer test-writer'
    with pytest.raises(HTTPException) as refused:
        await startup_routes.scope_route(command, request)
    assert refused.value.status_code == 401
