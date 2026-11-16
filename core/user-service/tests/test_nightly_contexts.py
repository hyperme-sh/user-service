"""Native contexts route and PostgreSQL; provider identity and registry are substituted."""
import json
import uuid
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from auth_service.schemas import AuthMeResponse
from user_service.deps import get_current_user
from controlplane_identity import nightly
from controlplane_identity.nightly_http import Authority, RunMiddleware
from test_fixture_bootstrap import bootstrap, MANIFEST


async def test_native_contexts_finish_before_owner_completion(empty_authority_owner,monkeypatch):
    from user_service.app import create_app
    bootstrap(empty_authority_owner)
    monkeypatch.setenv('USER_SCOPED_AUTHORITY_REQUIRED','1')
    monkeypatch.setattr(nightly,'_subjects',frozenset())
    subject=next(a['id'] for a in MANIFEST['accounts'] if a['key']=='network-admin')
    tenant=next(t['id'] for t in MANIFEST['tenants'] if t['key']=='active')
    scope=dict(suite='flags-portal-browser',subject=subject,tenant=tenant,organization='',realm='controlplane',issuer='https://auth.test.hyperme.sh/realms/controlplane',clients=['controlplane-frontend'],origins=['https://portal.test.hyperme.sh'],identities={'sea':[]})
    binding=dict(version=1,owner='user',run='123-1-flags-portal-browser',generation='c'*64,scope=scope,operation=str(uuid.uuid4()))
    config=dict(version=1,owner='user',origin='https://api.test.hyperme.sh',authOrigin='https://api.test.hyperme.sh',ownerKey='a'*64,controllerKey='b'*64,scopes={scope['suite']:scope})
    calls=[];active=[True]
    def registry(request):
        command=json.loads(request.content);calls.append(command['action'])
        if command['action']=='admit':return httpx.Response(200,json=binding) if active[0] else httpx.Response(409)
        assert command['action']=='complete'
        return httpx.Response(200,json={k:binding[k] for k in ('version','owner','run','generation','operation')}|{'completed':True})
    engine=create_async_engine(empty_authority_owner.url.set(drivername='postgresql+asyncpg'))
    app=create_app(test_event_sink=[]);app.state.session_maker=async_sessionmaker(engine)
    app.dependency_overrides[get_current_user]=lambda:AuthMeResponse(sub=subject,tenant_id=uuid.UUID(tenant))
    app.add_middleware(RunMiddleware,authority=Authority(config,'user',httpx.MockTransport(registry)),paths={('GET','/api/v1/authority/contexts')},control_path='/api/v1/user/internal/nightly-run')
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url=config['origin']) as client:
            headers={'X-Nightly-Run-Grant':'d'*64}
            response=await client.get('/api/v1/authority/contexts',headers=headers)
            assert response.status_code==200,response.text
            assert [t['id'] for t in response.json()['tenants']]==[tenant]
            assert calls==['admit','complete']
            assert (await client.post('/api/v1/organizations',headers=headers,json={})).status_code==409
            active[0]=False
            assert (await client.get('/api/v1/authority/contexts',headers=headers)).status_code==409
    finally:await engine.dispose()


async def test_native_organization_read_refuses_foreign_tenant_before_database():
    import pytest
    from jwt import InvalidTokenError
    from user_service.interfaces.api.routes import list_organizations
    subject='11111111-1111-4111-8111-111111111111'
    tenant='22222222-2222-4222-8222-222222222222'
    binding=dict(version=1,owner='user',run='123-1-flags-portal-browser',generation='c'*64,operation=str(uuid.uuid4()),
        scope=dict(suite='flags-portal-browser',subject=subject,tenant=tenant,organization=str(uuid.uuid4())))
    with nightly.admitted_run(binding):
        with pytest.raises(InvalidTokenError):
            await list_organizations(tenant_id=uuid.uuid4(),me=AuthMeResponse(sub=subject),session=None,limit=50,offset=0,q=None)
