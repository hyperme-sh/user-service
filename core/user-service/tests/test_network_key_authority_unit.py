"""Owner-check unit tests with database and current-authority doubles."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import Request, Response
import pytest

from user_service import key_authority as owner


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["objects", "records"])
@pytest.mark.parametrize('operation',['read','mint','manage','use'])
async def test_current_tenant_actor_status_is_rechecked_before_network_grant(monkeypatch,operation,family):
    tenant=uuid4()
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
        purpose=None if operation=='read' else 'service',scopes=[] if operation=='read' else [f'storage:{family}:read'])
    request=Request({'type':'http','method':'POST','path':'/','headers':[(b'x-tenant-id',str(tenant).encode())],
        'app':SimpleNamespace(state=SimpleNamespace(session_maker=lambda:session))})
    assert (await owner.lookup(body,request,Response()))['allowed'] is True
    active.assert_awaited_once_with(session,tenant,'network-admin')
    active.return_value=False
    assert (await owner.lookup(body,request,Response()))['allowed'] is False
    assert active.await_count==2 and grant.await_count==1
