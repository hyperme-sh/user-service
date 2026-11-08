"""Local disposable authority tests; no shared TEST identities are provisioned."""
from pathlib import Path
from types import SimpleNamespace
import uuid

from asgi_lifespan import LifespanManager
import httpx
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from controlplane_events.owner_schema import migrate
from auth_service.schemas import AuthMeResponse
from user_service.scope_schema import install
from user_service.scope_authority import organization_member


@pytest.fixture
async def scope_owner(postgres_sync_url, monkeypatch):
    from api.core.config import settings
    from user_service.app import create_app
    from user_service.deps import get_current_user
    from auth_service.deps import get_current_tenant, get_access_token_claims
    name='local_scope_'+uuid.uuid4().hex;reader=name+'_reader';password=uuid.uuid4().hex
    root=create_engine(postgres_sync_url)
    with root.begin() as db:
        for role in (name,reader):db.exec_driver_sql(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS')
        db.exec_driver_sql(f'CREATE SCHEMA "{name}" AUTHORIZATION "{name}"')
        for role in (name,reader):db.exec_driver_sql(f'ALTER ROLE "{role}" SET search_path TO "{name}"')
    owner=create_engine(make_url(postgres_sync_url).set(username=name,password=password))
    ddl=Path(__file__).with_name('fixtures').joinpath('scope-authority.sql').read_text()
    migrate(owner,revision='0001_owner_schema',ddl=Path(__file__).with_name('fixtures').joinpath('owner-schema.sql').read_text())
    with owner.begin() as db:
        install(db,ddl);install(db,ddl)
    admin=create_engine(postgres_sync_url,connect_args={'options':'-csearch_path='+name})
    s=SimpleNamespace(tenant=uuid.uuid4(),inactive=uuid.uuid4(),org=uuid.uuid4(),other=uuid.uuid4(),isolated=uuid.uuid4(),users={})
    with admin.begin() as db:
        db.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{name}" TO "{reader}"')
        db.exec_driver_sql(f'GRANT SELECT ON ALL TABLES IN SCHEMA "{name}" TO "{reader}"')
        db.exec_driver_sql(f'GRANT INSERT,UPDATE,DELETE ON identity_org_memberships TO "{reader}"')
        db.execute(text("INSERT INTO identity_scope_generation VALUES(true,'local-v1',:digest)"),{'digest':'a'*64})
        for network in ('local-a','local-b','local-c'):db.execute(text('INSERT INTO identity_networks VALUES(:network,true)'),{'network':network})
        for tenant,active in [(s.tenant,True),(s.inactive,False)]:
            db.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,:active)'),{'id':tenant,'name':str(tenant),'active':active})
            db.execute(text("INSERT INTO identity_network_tenants VALUES(:tenant,'local-a')"),{'tenant':tenant})
        for org,tenant in [(s.org,s.tenant),(s.other,s.tenant),(s.isolated,s.inactive)]:db.execute(text('INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:id,:tenant,:name)'),{'id':org,'tenant':tenant,'name':str(org)})
        for key,tenant in [('network-a',None),('network-b',None),('network-c',None),('admin',s.tenant),('payer',s.tenant),('member',s.tenant),('disabled',s.tenant),('other-admin',s.tenant),('other-payer',s.tenant),('isolated-admin',s.inactive),('isolated-member',s.inactive),('unassociated',None)]:
            user=uuid.uuid4();s.users[key]=user
            db.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,:tenant,:sub,:email,'Local','Actor','unspecified',:active)"),{'id':user,'tenant':tenant,'sub':'local:'+key,'email':key+'@local.invalid','active':key!='disabled'})
        isolation_role=uuid.uuid4()
        db.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:role,:tenant,'admin','[]'::jsonb)"),{'role':isolation_role,'tenant':s.inactive})
        db.execute(text('UPDATE users SET role_id=:role WHERE id=:user'),{'role':isolation_role,'user':s.users['isolated-admin']})
        for network in ('a','b','c'):db.execute(text('INSERT INTO identity_network_admins VALUES(:network,:user,true)'),{'network':'local-'+network,'user':s.users['network-'+network]})
        for key,tenant,org,role,billing in [('admin',s.tenant,s.org,'admin',True),('payer',s.tenant,s.org,'member',True),('member',s.tenant,s.org,'member',False),('disabled',s.tenant,s.org,'member',False),('other-admin',s.tenant,s.other,'admin',True),('other-payer',s.tenant,s.other,'member',True),('isolated-admin',s.inactive,s.isolated,'admin',False),('isolated-member',s.inactive,s.isolated,'member',False)]:
            db.execute(text('INSERT INTO identity_org_memberships VALUES(:tenant,:org,:user,:role,:billing,true)'),{'tenant':tenant,'org':org,'user':s.users[key],'role':role,'billing':billing})
    url=make_url(postgres_sync_url).set(drivername='postgresql+asyncpg',username=reader,password=password).render_as_string(hide_password=False)
    monkeypatch.setattr(settings,'database_url',url)
    monkeypatch.setenv('USER_SCOPE_GENERATION','local-v1')
    for caller in ('AUTH','PAYMENT','PLANE'):monkeypatch.setenv(caller+'_SCOPE_AUTHORITY_TOKEN','local-'+caller)
    s.actor='admin';s.signed_tenant=s.tenant;s.signed_org=s.org;s.signed_network="local-a";s.admin=admin
    app=create_app(test_event_sink=[])
    async def me():return AuthMeResponse(sub='local:'+s.actor,email=s.actor+'@local.invalid',roles=['admin'],groups=['admin'])
    async def tenant():return s.signed_tenant
    async def claims():return {'sub':'local:'+s.actor,'tenant_id':str(s.signed_tenant),'spanopticon_auth':'tenant_session','scope_version':1,'organization_id':str(s.signed_org),'network_id':s.signed_network,'scope_generation':'local-v1','scope_manifest_sha256':'a'*64}
    app.dependency_overrides[get_current_user]=me;app.dependency_overrides[get_current_tenant]=tenant
    app.dependency_overrides[get_access_token_claims]=claims
    try:
        async with LifespanManager(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='http://scope.local') as c:
                s.client=c;s.app=app;yield s
    finally:
        owner.dispose();admin.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP SCHEMA "{name}" CASCADE')
            for role in (reader,name):
                db.exec_driver_sql(f'DROP OWNED BY "{role}"');db.exec_driver_sql(f'DROP ROLE "{role}"')
        root.dispose()


@pytest.mark.parametrize('network',['a','b','c'])
async def test_each_network_admin_has_only_own_network_authority(scope_owner,network):
    s=scope_owner;s.actor='network-'+network
    for target in ('a','b','c'):
        r=await s.client.get('/api/v1/networks/local-'+target+'/authority')
        assert r.status_code==(200 if target==network else 403),r.text


@pytest.mark.parametrize('actor,org,tenant,capability,allowed',[
 ('admin','primary','active','manage-members',True),('admin','other','active','manage-members',False),
 ('other-admin','other','active','manage-members',True),('other-admin','primary','active','manage-members',False),
 ('payer','primary','active','purchase',True),('payer','other','active','purchase',False),
 ('other-payer','other','active','purchase',True),('member','primary','active','purchase',False),
 ('member','primary','active','member',True),('disabled','primary','active','member',False),
 ('unassociated','primary','active','member',False),('network-a','primary','active','manage-members',False),
 ('isolated-admin','primary','active','manage-members',False),('isolated-admin','isolated','inactive','manage-members',False),
 ('isolated-member','isolated','inactive','member',False),('payer','primary','inactive','member',False)])
async def test_current_owner_contract_refuses_unrelated_scopes(scope_owner,actor,org,tenant,capability,allowed):
    s=scope_owner;org_id={'primary':s.org,'other':s.other,'isolated':s.isolated}[org];tid=s.tenant if tenant=='active' else s.inactive
    caller='PAYMENT' if capability=='purchase' else 'AUTH'
    r=await s.client.post('/api/v1/internal/organization-authority/check',headers={'Authorization':'Bearer local-'+caller},json={'subject':'local:'+actor,'tenant_id':str(tid),'organization_id':str(org_id),'capability':capability})
    assert r.status_code==200,r.text
    assert (r.json() is not None)==allowed
    if allowed:assert r.json()['user_id']==str(s.users[actor])


async def test_scoped_crud_and_refusals_leave_other_org_unchanged(scope_owner):
    s=scope_owner;headers={'X-Tenant-ID':str(s.tenant)};target=s.users['payer']
    with s.admin.connect() as db:before=db.execute(text('SELECT * FROM identity_org_memberships ORDER BY organization_id,user_id')).all()
    for path in [f'/api/v1/organizations/{s.other}/members/{target}',f'/api/v1/organizations/{s.isolated}/members/{target}']:
        assert (await s.client.put(path,headers=headers,json={'role':'admin','can_purchase':True})).status_code==403
        assert (await s.client.delete(path,headers=headers)).status_code==403
    with s.admin.connect() as db:assert db.execute(text('SELECT * FROM identity_org_memberships ORDER BY organization_id,user_id')).all()==before
    own=f'/api/v1/organizations/{s.org}/members/{target}'
    assert (await s.client.put(own,headers=headers,json={'role':'member','can_purchase':False})).status_code==200
    assert (await s.client.get(f'/api/v1/organizations/{s.org}/members',headers=headers)).status_code==200
    assert (await s.client.delete(own,headers=headers)).status_code==204
    assert (await s.client.put(own,headers=headers,json={'role':'member','can_purchase':True})).status_code==200
    for payload in [{'role':'network-admin'},{'role':'tenant-admin'},{'network_id':'local-a'},{'tenant_id':str(s.inactive)}]:
        assert (await s.client.put(own,headers=headers,json=payload)).status_code==422


@pytest.mark.parametrize('change',['disabled','revoked','banned'])
async def test_stale_admin_claims_cannot_override_current_membership(scope_owner,change):
    s=scope_owner
    with s.admin.begin() as db:
        if change=='disabled':db.execute(text('UPDATE users SET is_active=false WHERE id=:user'),{'user':s.users['admin']})
        elif change=='revoked':db.execute(text('UPDATE identity_org_memberships SET active=false WHERE user_id=:user'),{'user':s.users['admin']})
        else:db.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,'user',:user,'local','local',now())"),{'id':uuid.uuid4(),'tenant':s.tenant,'user':s.users['admin']})
    r=await s.client.get(f'/api/v1/organizations/{s.org}/members',headers={'X-Tenant-ID':str(s.tenant)})
    assert r.status_code==403


async def test_header_substitution_and_legacy_routes_cannot_bypass_scope(scope_owner):
    s=scope_owner
    assert (await s.client.get(f'/api/v1/organizations/{s.org}/members',headers={'X-Tenant-ID':str(s.inactive)})).status_code==403
    for path in ['/api/v1/users','/api/v1/organizations','/api/v1/groups','/api/v1/operator/session']:
        r=await s.client.get(path,headers={'X-Tenant-ID':str(s.tenant),'X-Organization-ID':str(s.org),'X-Role':'admin'})
        assert r.status_code==403,(path,r.status_code,r.text)


async def test_service_credentials_and_capability_boundaries(scope_owner,monkeypatch):
    s=scope_owner;body={'subject':'local:admin','tenant_id':str(s.tenant),'organization_id':str(s.org),'capability':'manage-members'}
    for credential in ['', 'browser-token','local-PAYMENT','local-PLANE']:
        r=await s.client.post('/api/v1/internal/organization-authority/check',headers={'Authorization':'Bearer '+credential},json=body)
        assert r.status_code==(403 if credential.startswith('local-') else 401)
    monkeypatch.setenv('PAYMENT_SCOPE_AUTHORITY_TOKEN','local-AUTH')
    assert (await s.client.post('/api/v1/internal/organization-authority/check',headers={'Authorization':'Bearer local-AUTH'},json=body)).status_code==401


@pytest.mark.parametrize('actor',['payer','member','other-admin','disabled','unassociated','network-a','isolated-admin','isolated-member'])
async def test_non_org_admins_cannot_use_member_administration(scope_owner,actor):
    s=scope_owner;s.actor=actor
    r=await s.client.get(f'/api/v1/organizations/{s.org}/members',headers={'X-Tenant-ID':str(s.tenant)})
    assert r.status_code==403
    with s.admin.connect() as db:
        assert db.scalar(text('SELECT r.name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=:id'),{'id':s.users['isolated-admin']})=='admin'


async def test_cross_tenant_membership_rejected_by_database(scope_owner):
    from sqlalchemy.exc import IntegrityError
    s=scope_owner
    with pytest.raises(IntegrityError):
        with s.admin.begin() as db:
            db.execute(text("INSERT INTO identity_org_memberships VALUES(:tenant,:org,:user,'member',true,true)"),{'tenant':s.tenant,'org':s.org,'user':s.users['isolated-member']})


@pytest.mark.parametrize('generation',['','wrong-generation'])
async def test_unready_generation_is_unavailable_not_scope_acceptance(scope_owner,monkeypatch,generation):
    s=scope_owner;monkeypatch.setenv('USER_SCOPE_GENERATION',generation)
    assert (await s.client.get(f'/api/v1/organizations/{s.org}/members',headers={'X-Tenant-ID':str(s.tenant)})).status_code==503


@pytest.mark.parametrize('operation',['enroll','tenant-switch','tenant-switch-current','host-setup','session-member','seed-operator','seed-host','provision-operator'])
async def test_legacy_identity_grants_cannot_bypass_explicit_generation(scope_owner,monkeypatch,operation):
    s=scope_owner;monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN','local-legacy-auth')
    r=await s.client.post('/api/v1/internal/identity/'+operation,headers={'Authorization':'Bearer local-legacy-auth'},json={'subject':'local:admin','tenant_id':str(s.tenant)})
    assert r.status_code==403


async def test_signed_org_selection_cannot_be_substituted_even_with_two_memberships(scope_owner):
    s=scope_owner
    with s.admin.begin() as db:db.execute(text("INSERT INTO identity_org_memberships VALUES(:tenant,:org,:user,'admin',true,true)"),{'tenant':s.tenant,'org':s.other,'user':s.users['admin']})
    headers={'X-Tenant-ID':str(s.tenant),'X-Organization-ID':str(s.other)}
    path=f'/api/v1/organizations/{s.other}/members'
    assert (await s.client.get(path,headers=headers)).status_code==403
    s.signed_org=s.other
    assert (await s.client.get(path,headers=headers)).status_code==200
    s.signed_network='local-b'
    assert (await s.client.get(path,headers=headers)).status_code==403


async def test_inactive_local_admin_assignment_is_preserved(scope_owner):
    s=scope_owner
    with s.admin.connect() as db:
        row=db.execute(text('SELECT m.role,m.active,t.is_active FROM identity_org_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.user_id=:id'),{'id':s.users['isolated-admin']}).one()
        assert tuple(row)==('admin',True,False)


async def test_disabled_target_cannot_be_reactivated_through_membership_crud(scope_owner):
    s=scope_owner
    r=await s.client.put(f'/api/v1/organizations/{s.org}/members/{s.users["disabled"]}',headers={'X-Tenant-ID':str(s.tenant)},json={'role':'admin','active':True,'can_purchase':True})
    assert r.status_code==403
    with s.admin.connect() as db:assert db.scalar(text('SELECT is_active FROM users WHERE id=:id'),{'id':s.users['disabled']}) is False


@pytest.mark.parametrize('actor,org_key,payer',[('admin','org','payer'),('other-admin','other','other-payer')])
async def test_each_org_admin_can_manage_only_its_own_members(scope_owner,actor,org_key,payer):
    s=scope_owner;s.actor=actor;s.signed_org=getattr(s,org_key)
    base=f'/api/v1/organizations/{s.signed_org}/members';target=base+'/'+str(s.users[payer]);headers={'X-Tenant-ID':str(s.tenant)}
    assert (await s.client.get(base,headers=headers)).status_code==200
    assert (await s.client.put(target,headers=headers,json={'role':'member','can_purchase':False})).status_code==200
    assert (await s.client.delete(target,headers=headers)).status_code==204
    assert (await s.client.put(target,headers=headers,json={'role':'member','can_purchase':True})).status_code==200


async def test_private_scope_check_never_authenticates_service_token_as_browser(scope_owner):
    from auth_service.deps import get_access_token_claims
    s=scope_owner
    async def forbidden():raise AssertionError('Private service token is not a browser credential')
    s.app.dependency_overrides[get_access_token_claims]=forbidden
    r=await s.client.post('/api/v1/internal/organization-authority/check',headers={'Authorization':'Bearer local-AUTH'},json={'subject':'local:admin','tenant_id':str(s.tenant),'organization_id':str(s.org)})
    assert r.status_code==200 and r.json()['organization_id']==str(s.org)
