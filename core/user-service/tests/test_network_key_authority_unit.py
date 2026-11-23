"""Owner-check unit tests with database and current-authority doubles."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

from fastapi import Request, Response
import pytest

from user_service import key_authority as owner


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [["storage:objects:read"], ["storage:records:read"],
    ["storage:media:observe"], ["storage:allocations:issue"], ["storage:media:retire"],
    ["storage:media:payload:read", "storage:media:payload:write"], ["acl:media:read", "acl:media:write"],
    ["storage:replays:consume"], ["storage:objects:read", "storage:objects:write", "storage:media:read", "storage:media:write"]])
@pytest.mark.parametrize('operation',['read','mint','manage','use'])
@pytest.mark.parametrize('canonical_test', [True, False])
async def test_current_tenant_actor_status_is_rechecked_before_network_grant(monkeypatch,operation,scopes,canonical_test):
    tenant=UUID(owner.S3RCH_TEST_TENANT['id']) if canonical_test else uuid4()
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
        def begin(self): return self
        async def execute(self,*args):
            return SimpleNamespace(one_or_none=lambda:('unit','a'*64))
    session=Session()
    monkeypatch.setattr(owner,'active_tenant',AsyncMock(return_value=True))
    monkeypatch.setattr(owner,'tenant_network',AsyncMock(return_value='s3r.ch'))
    active=AsyncMock(return_value=True)
    grant=AsyncMock(return_value=True)
    monkeypatch.setattr(owner,'actor_active',active)
    monkeypatch.setattr(owner,'allowed',grant)
    body=owner.Query(request_id=uuid4(),subject='network-admin',tenant_id=tenant,network_id='s3r.ch',
        scope_kind='network',generation='unit',manifest_sha256='a'*64,operation=operation,
        purpose=None if operation=='read' else 'service',scopes=[] if operation=='read' else scopes)
    request=Request({'type':'http','method':'POST','path':'/','headers':[(b'x-tenant-id',str(tenant).encode())],
        'app':SimpleNamespace(state=SimpleNamespace(session_maker=lambda:session))})
    test_only = operation != 'read' and scopes in (
        ['storage:media:observe'], ['storage:allocations:issue'], ['storage:media:retire'],
        ['storage:media:payload:read', 'storage:media:payload:write'], ['acl:media:read', 'acl:media:write'],
    )
    assert (await owner.lookup(body,request,Response()))['allowed'] is (canonical_test or not test_only)
    active.assert_awaited_once_with(session,tenant,'network-admin')
    active.return_value=False
    assert (await owner.lookup(body,request,Response()))['allowed'] is False
    assert active.await_count==2 and grant.await_count==1


@pytest.mark.asyncio
@pytest.mark.parametrize('change', [
    '', 'network', 'tenant', 'fixture-member', 'other-admin', 'generation',
    'stale-seal', 'purpose', 'mixed', 'duplicate', 'inactive-owner', 'missing-grant',
])
async def test_portal_media_key_authority_is_exact(monkeypatch, change):
    from fastapi import HTTPException

    tenant = uuid4() if change == 'tenant' else owner.PORTAL_TEST_TENANT
    network = 'tennesseewindage' if change == 'network' else 'hyperme.sh'
    subject = {
        'fixture-member': 'c92fc0dd-c922-5c71-88da-bd91b38d14a4',
        'other-admin': str(uuid4()),
    }.get(change, owner.PORTAL_TEST_NETWORK_OWNER)
    generation = 'other' if change == 'generation' else 'test-reset-v1'
    scopes = ['storage:media:payload:read']
    if change == 'mixed':
        scopes.append('storage:media:retire')
    elif change == 'duplicate':
        scopes *= 2

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        def begin(self):
            return self

        async def execute(self, *_):
            seal = 'b' * 64 if change == 'stale-seal' else 'a' * 64
            return SimpleNamespace(one_or_none=lambda: (generation, seal))

    monkeypatch.setattr(owner, 'active_tenant', AsyncMock(return_value=True))
    monkeypatch.setattr(owner, 'tenant_network', AsyncMock(return_value=network))
    monkeypatch.setattr(owner, 'actor_active', AsyncMock(return_value=change != 'inactive-owner'))
    monkeypatch.setattr(owner, 'allowed', AsyncMock(return_value=change != 'missing-grant'))
    query = owner.Query(
        request_id=uuid4(), subject=subject, tenant_id=tenant, network_id=network,
        scope_kind='network', generation=generation, manifest_sha256='a' * 64,
        operation='mint', purpose='ir' if change == 'purpose' else 'service', scopes=scopes,
    )
    request = Request({
        'type': 'http', 'method': 'POST', 'path': '/',
        'headers': [(b'x-tenant-id', str(tenant).encode())],
        'app': SimpleNamespace(state=SimpleNamespace(session_maker=Session)),
    })
    if change == 'stale-seal':
        with pytest.raises(HTTPException) as refused:
            await owner.lookup(query, request, Response())
        assert refused.value.status_code == 403
    else:
        assert (await owner.lookup(query, request, Response()))['allowed'] is (change == '')
