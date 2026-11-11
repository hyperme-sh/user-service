"""Actual User authority facts for persistent keys, not client-supplied grants."""
import uuid

from fastapi import FastAPI
import httpx
import pytest
from sqlalchemy import text

from test_scoped_authority import authority
from user_service.key_authority import router
from user_service.scoped_authority import scope


@pytest.fixture
async def key_facts(authority,monkeypatch,tmp_path):
    s=authority
    async with s.maker() as db,db.begin():
        await db.execute(text('''INSERT INTO authority_fixture_generation
            (generation,manifest_sha256,subjects_sha256,source_sha) VALUES('isolated',:manifest,:subjects,:source)'''),
            {'manifest':'a'*64,'subjects':'b'*64,'source':'c'*40})
    credential=tmp_path/'key';credential.write_text('d'*64);credential.chmod(0o600)
    monkeypatch.setenv('API_KEYS_AUTHORITY_TOKEN_FILE',str(credential))
    app=FastAPI();app.include_router(router,prefix='/api/v1');app.state.session_maker=s.maker
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='http://owner.test') as client:
        yield s,client


async def query(s,client,subject='payer',operation='use',purpose='renter',**overrides):
    value=dict(version=1,request_id=str(uuid.uuid4()),subject=subject,tenant_id=str(s.tenant),
        network_id='hyperme.sh',organization_id=str(s.org),scope_kind='organization',
        generation='isolated',manifest_sha256='a'*64,operation=operation,purpose=purpose,scopes=[])
    value.update(overrides)
    response=await client.post('/api/v1/internal/key-authority',
        headers={'Authorization':'Bearer '+'d'*64,'X-Tenant-ID':value['tenant_id']},json=value)
    if response.status_code==200:
        body=response.json()
        assert all(body[k]==v for k,v in value.items())
        assert type(body['allowed']) is bool and type(body['org_admin']) is bool
        assert response.headers['cache-control']=='no-store'
    return response


@pytest.mark.parametrize('subject,purpose,expected',[
    ('payer','renter',True),('member','renter',False),('disabled','renter',False),
    ('other-org-admin','renter',False),('wrongadmin','renter',False),
    ('org-admin','ir',True),('payer','ir',False),('org-admin','service',True),
])
async def test_current_key_owner_authority(key_facts,subject,purpose,expected):
    s,c=key_facts
    response=await query(s,c,subject=subject,purpose=purpose)
    assert response.status_code==200 and response.json()['allowed'] is expected


async def test_membership_revocation_stops_persistent_key_authority(key_facts):
    s,c=key_facts
    assert (await query(s,c)).json()['allowed'] is True
    async with s.maker() as db,db.begin(),scope(db,s.tenant):
        await db.execute(text('UPDATE organization_memberships SET enabled=false WHERE tenant_id=:tenant AND user_id=:user'),
                         {'tenant':s.tenant,'user':s.users['payer']})
    assert (await query(s,c)).json()['allowed'] is False


async def test_scope_seal_and_purpose_service_credential_are_required(key_facts):
    s,c=key_facts
    assert (await query(s,c,manifest_sha256='f'*64)).status_code==403
    response=await c.post('/api/v1/internal/key-authority',headers={'Authorization':'Bearer unrelated'},json={})
    assert response.status_code==401
    assert (await query(s,c,subject='apikey:'+str(uuid.uuid4()))).json()['allowed'] is False
    assert (await query(s,c,network_id='s3r.ch')).json()['allowed'] is False


async def test_read_only_facts_and_member_revoke_permission(key_facts,monkeypatch):
    from user_service import key_authority
    s,c=key_facts
    original=key_authority.active_tenant
    async def readonly(session,tenant):
        assert await session.scalar(text('SHOW transaction_read_only'))=='on'
        return await original(session,tenant)
    monkeypatch.setattr(key_authority,'active_tenant',readonly)
    assert (await query(s,c,subject='member',operation='manage')).json()['allowed'] is True
    assert (await query(s,c,subject='member',operation='read',purpose=None)).json()['allowed'] is True


@pytest.mark.parametrize('subject,purpose',[('payer','renter'),('org-admin','renter'),('org-admin','ir'),('org-admin','service')])
async def test_org_key_cannot_claim_network_or_unknown_scopes(key_facts,subject,purpose):
    s,c=key_facts
    for scopes in (['oracles:attest'],['unknown:scope']):
        response=await query(s,c,subject=subject,purpose=purpose,scopes=scopes)
        assert response.status_code==200 and response.json()['allowed'] is False


async def test_capabilities_require_the_same_purpose_credential(key_facts):
    _,c=key_facts
    response=await c.get('/api/v1/internal/key-authority/capabilities',headers={'Authorization':'Bearer '+'d'*64})
    assert response.status_code==200 and response.json()=={'api_key_authority_version':1}
    assert (await c.get('/api/v1/internal/key-authority/capabilities')).status_code==401


@pytest.mark.parametrize('operation',['read','mint','manage','use'])
async def test_network_admin_cannot_bypass_organization_scope_allowlist(key_facts,operation):
    s,c=key_facts
    async with s.maker() as db,db.begin(),scope(db,s.tenant):
        await db.execute(text("UPDATE authority_tenants SET network_id='s3r.ch' WHERE tenant_id=:tenant"),{'tenant':s.tenant})
    # A legitimate s3r.ch network service grant remains usable on its own door.
    positive=await query(s,c,subject='other-network-admin',operation=operation,purpose=None if operation=='read' else 'service',
        network_id='s3r.ch',scope_kind='network',organization_id=None,scopes=['oracles:attest'])
    assert positive.status_code==200,positive.text
    assert positive.json()['allowed'] is True
    refused=await query(s,c,subject='other-network-admin',operation=operation,purpose=None if operation=='read' else 'service',
        network_id='s3r.ch',scopes=['oracles:attest'])
    assert refused.status_code==200,refused.text
    assert refused.json()['allowed'] is False and refused.json()['org_admin'] is False


@pytest.mark.parametrize('operation',['mint','manage','use'])
@pytest.mark.parametrize('scopes',[
    ['storage:objects:read'], ['storage:objects:write'], ['storage:objects:delete'],
    ['storage:objects:read','storage:objects:write','storage:objects:delete'],
])
async def test_storage_service_key_requires_current_s3rch_network_admin(key_facts,operation,scopes):
    s,c=key_facts
    async with s.maker() as db,db.begin(),scope(db,s.tenant):
        await db.execute(text("UPDATE authority_tenants SET network_id='s3r.ch' WHERE tenant_id=:tenant"),{'tenant':s.tenant})
    selected=dict(operation=operation,purpose='service',network_id='s3r.ch',scope_kind='network',organization_id=None,scopes=scopes)
    assert (await query(s,c,subject='other-network-admin',**selected)).json()['allowed'] is True
    assert (await query(s,c,subject='payer',**selected)).json()['allowed'] is False
    assert (await query(s,c,subject='org-admin',**selected)).json()['allowed'] is False
    assert (await query(s,c,subject='other-network-admin',**{**selected,'scope_kind':'organization','organization_id':str(s.org)})).json()['allowed'] is False
    assert (await query(s,c,subject='other-network-admin',**{**selected,'scopes':scopes+['oracles:attest']})).json()['allowed'] is False
    assert (await query(s,c,subject='other-network-admin',**{**selected,'manifest_sha256':'f'*64})).status_code == 403
