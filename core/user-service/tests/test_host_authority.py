"""Purpose-authenticated HTTP facts under a SELECT-only tenant-scoped role."""
from types import SimpleNamespace
import uuid

from fastapi import FastAPI
import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from user_service.host_authority import router
from user_service.identity_api import router as commands

@pytest.fixture
async def facts_owner(migrated_sync_url, monkeypatch, tmp_path):
    root=create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg'))
    s=SimpleNamespace(tenant=uuid.uuid4(),other=uuid.uuid4(),user=uuid.uuid4(),role=uuid.uuid4(),group=uuid.uuid4(),device=uuid.uuid4(),subject='host:'+uuid.uuid4().hex)
    name='facts_reader_'+uuid.uuid4().hex;password=uuid.uuid4().hex
    async with root.begin() as db:
        await db.execute(text(f'CREATE ROLE "{name}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
        await db.execute(text(f'GRANT USAGE ON SCHEMA public TO "{name}"'))
        await db.execute(text(f'GRANT SELECT ON tenants,users,roles,groups,user_group_memberships,operator_bans TO "{name}"'))
        for tenant in (s.tenant,s.other):
            await db.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'),{'id':tenant,'name':str(tenant)})
        await db.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,'host','[]'::jsonb)"),{'id':s.role,'tenant':s.tenant})
        await db.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id) VALUES(:id,:tenant,:sub,'host@example.invalid','Native','Host','unspecified',true,:role)"),{'id':s.user,'tenant':s.tenant,'sub':s.subject,'role':s.role})
        await db.execute(text("INSERT INTO groups(id,tenant_id,name,role_id) VALUES(:id,:tenant,'host',:role)"),{'id':s.group,'tenant':s.tenant,'role':s.role})
    engine=create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg',username=name,password=password))
    app=FastAPI();app.include_router(router,prefix='/api/v1');app.include_router(commands,prefix='/api/v1')
    app.state.session_maker=async_sessionmaker(engine,expire_on_commit=False)
    key=tmp_path/'key';key.write_text('a'*64);key.chmod(0o600)
    monkeypatch.setenv('HOST_IDENTITY_OWNER_TOKEN_FILE',str(key));monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN','b'*64)
    s.root,s.engine,s.key=root,engine,key
    s.headers={'Authorization':'Bearer '+'a'*64,'X-Tenant-ID':str(s.tenant)}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='http://owner.test') as client:
            s.client=client;yield s
    finally:
        await engine.dispose()
        async with root.begin() as db:
            for table in ('operator_bans','user_group_memberships','groups','users','roles'):
                await db.execute(text(f'DELETE FROM {table} WHERE tenant_id IN (:a,:b)'),{'a':s.tenant,'b':s.other})
            await db.execute(text('DELETE FROM tenants WHERE id IN (:a,:b)'),{'a':s.tenant,'b':s.other})
            await db.execute(text(f'DROP OWNED BY "{name}"'));await db.execute(text(f'DROP ROLE "{name}"'))
        await root.dispose()

async def query(s,operation='tenant-active',headers=None,**fields):
    body={'version':1,'request_id':str(uuid.uuid4()),'tenant_id':str(s.tenant),'operation':operation,**fields}
    response=await s.client.post('/api/v1/internal/host-authority',headers=s.headers if headers is None else headers,json=body)
    if response.status_code==200:
        assert response.json()['request_id']==body['request_id'] and response.json()['tenant_id']==body['tenant_id']
        assert response.headers['cache-control']=='no-store'
    return response

async def test_tenant_status_and_read_only_transaction(facts_owner,monkeypatch):
    s=facts_owner
    from user_service import host_authority
    original=host_authority.set_current_tenant_id_guc
    async def readonly(session,tenant):
        assert await session.scalar(text('SHOW transaction_read_only'))=='on'
        return await original(session,tenant)
    monkeypatch.setattr(host_authority,'set_current_tenant_id_guc',readonly)
    assert (await query(s)).json()['active'] is True
    async with s.root.begin() as db:await db.execute(text('UPDATE tenants SET is_active=false WHERE id=:id'),{'id':s.tenant})
    assert (await query(s)).json()['active'] is False
    other=uuid.uuid4();headers=dict(s.headers,**{'X-Tenant-ID':str(other)})
    assert (await query(s,headers=headers,tenant_id=str(other))).json()['active'] is None

async def test_bound_membership_and_host_group_identifiers(facts_owner):
    s=facts_owner
    first=(await query(s,'member',subject=s.subject)).json()['member']
    assert first['id']==str(s.user) and first['keycloak_sub']==s.subject and first['host_group'] is True
    assert (await query(s,'member',subject='other')).json()['member'] is None
    async with s.root.begin() as db:
        await db.execute(text('UPDATE users SET role_id=NULL WHERE id=:id'),{'id':s.user})
        await db.execute(text('INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id) VALUES(:id,:tenant,:user,:group)'),{'id':uuid.uuid4(),'tenant':s.tenant,'user':s.user,'group':s.group})
    group=(await query(s,'member',subject=s.subject)).json()['member']
    assert group['host_group'] is True and group['group_ids']==[str(s.group)]
    async with s.root.begin() as db:await db.execute(text('UPDATE users SET is_active=false WHERE id=:id'),{'id':s.user})
    inactive=(await query(s,'member',subject=s.subject)).json()['member']
    assert inactive is None or (inactive['is_active'] is False and inactive['host_group'] is False)

@pytest.mark.parametrize('kind',['user','group','device'])
async def test_durable_tenant_and_kind_scoped_bans(facts_owner,kind):
    s=facts_owner;subject=getattr(s,kind);field={'user':'users','group':'groups','device':'devices'}[kind]
    assert (await query(s,'bans',**{field:[str(subject)]})).json()['banned'] is False
    async with s.root.begin() as db:
        await db.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,:kind,:subject,'fixture','fixture',now())"),{'id':uuid.uuid4(),'tenant':s.tenant,'kind':kind,'subject':subject})
    assert (await query(s,'bans',**{field:[str(subject)]})).json()['banned'] is True
    headers=dict(s.headers,**{'X-Tenant-ID':str(s.other)})
    assert (await query(s,'bans',headers=headers,tenant_id=str(s.other),**{field:[str(subject)]})).json()['banned'] is False
    async with s.root.begin() as db:await db.execute(text('UPDATE operator_bans SET lifted_at=now() WHERE tenant_id=:tenant'),{'tenant':s.tenant})
    assert (await query(s,'bans',**{field:[str(subject)]})).json()['banned'] is False

@pytest.mark.parametrize('token',[None,'Bearer wrong','Bearer '+'b'*64,'Bearer human-session'])
async def test_wrong_purpose_cannot_read_identity(facts_owner,token):
    s=facts_owner;headers={'X-Tenant-ID':str(s.tenant)}
    if token:headers['Authorization']=token
    assert (await query(s,headers=headers)).status_code==401

async def test_read_key_cannot_issue_identity_commands(facts_owner):
    s=facts_owner
    reply=await s.client.post('/api/v1/internal/identity/host-setup',headers=s.headers,json={'subject':s.subject,'tenant_id':str(s.tenant)})
    assert reply.status_code==401
    headers=dict(s.headers,**{'X-Tenant-ID':str(s.other)})
    assert (await query(s,headers=headers)).status_code==403
    s.key.unlink();assert (await query(s)).status_code==503

@pytest.mark.parametrize('body',[{'operation':'unknown'},{'operation':'member'},{'operation':'member','subject':' '},{'operation':'bans','subject':'user'},{'operation':'bans','devices':['invalid']},{'operation':'bans','devices':[str(uuid.uuid4())]*17},{'claims':{'role':'admin'}},{'operation':'tenant-active','users':[str(uuid.uuid4())]}])
async def test_malformed_or_unbounded_queries_are_refused(facts_owner,body):
    assert (await query(facts_owner,**body)).status_code==422
