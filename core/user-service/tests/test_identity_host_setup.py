"""Actual authenticated owner HTTP and RLS reads for host-setup authority."""
from datetime import UTC, datetime
from types import SimpleNamespace
import uuid

from fastapi import FastAPI
import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.domain.operator.bans import ban_book
from user_service.identity_api import router


@pytest.fixture
async def host_owner(migrated_sync_url, monkeypatch):
    root = create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg'))
    s = SimpleNamespace(tenant=uuid.uuid4(), other=uuid.uuid4(), user=uuid.uuid4(),
        role=uuid.uuid4(), group=uuid.uuid4(), subject='opaque:host:' + uuid.uuid4().hex)
    role_name = 'host_reader_' + uuid.uuid4().hex
    password = uuid.uuid4().hex
    async with root.begin() as db:
        await db.execute(text(f'CREATE ROLE "{role_name}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
        await db.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
        await db.execute(text(f'GRANT SELECT ON tenants,users,roles,groups,user_group_memberships,operator_bans TO "{role_name}"'))
        for tenant in (s.tenant, s.other):
            await db.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'), {'id': tenant, 'name': str(tenant)})
        await db.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,'host','[]'::jsonb)"), {'id': s.role, 'tenant': s.tenant})
        await db.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id) VALUES(:id,:tenant,:sub,'host@example.invalid','Native','Host','unspecified',true,:role)"), {'id': s.user,'tenant': s.tenant,'sub': s.subject,'role': s.role})
        await db.execute(text("INSERT INTO groups(id,tenant_id,name,role_id) VALUES(:id,:tenant,'host',:role)"), {'id': s.group,'tenant': s.tenant,'role':s.role})
    engine = create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg',username=role_name,password=password))
    app = FastAPI(); app.include_router(router, prefix='/api/v1')
    app.state.session_maker = async_sessionmaker(engine,expire_on_commit=False)
    s.root, s.engine = root, engine
    s.headers = {'Authorization': 'Bearer fixture-auth-owner-token'}
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN','fixture-auth-owner-token')
    ban_book().clear()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='http://owner.test') as client:
            s.client = client
            yield s
    finally:
        await engine.dispose()
        async with root.begin() as db:
            for table in ('operator_bans','user_group_memberships','groups','users','roles'):
                await db.execute(text(f'DELETE FROM {table} WHERE tenant_id IN (:a,:b)'), {'a':s.tenant,'b':s.other})
            await db.execute(text('DELETE FROM tenants WHERE id IN (:a,:b)'), {'a':s.tenant,'b':s.other})
            await db.execute(text(f'DROP OWNED BY "{role_name}"'))
            await db.execute(text(f'DROP ROLE "{role_name}"'))
        ban_book().clear()
        await root.dispose()


async def command(s, **changes):
    body = {'subject': s.subject, 'tenant_id': str(s.tenant), **changes}
    return await s.client.post('/api/v1/internal/identity/host-setup',headers=s.headers,json=body)


@pytest.mark.parametrize('boundary', ['direct','group','inactive','closed','unbound','other-subject','other-tenant','inactive-tenant','renter','platform','banned','lifted','foreign-ban','other-kind-ban'])
async def test_native_host_authority_and_current_durable_bans(host_owner, boundary):
    s = host_owner
    args = {}
    async with s.root.begin() as db:
        if boundary == 'group':
            await db.execute(text('UPDATE users SET role_id=NULL WHERE id=:id'), {'id':s.user})
            await db.execute(text('INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id) VALUES(:id,:tenant,:user,:group)'), {'id':uuid.uuid4(),'tenant':s.tenant,'user':s.user,'group':s.group})
        if boundary in ('inactive','closed','unbound'):
            update = {'inactive':'is_active=false','closed':'deleted_at=now()','unbound':'keycloak_sub=NULL'}[boundary]
            await db.execute(text('UPDATE users SET '+update+' WHERE id=:id'), {'id':s.user})
        if boundary == 'inactive-tenant':
            await db.execute(text('UPDATE tenants SET is_active=false WHERE id=:id'), {'id':s.tenant})
        if boundary == 'renter':
            await db.execute(text("UPDATE roles SET name='renter' WHERE id=:id"), {'id':s.role})
        if boundary == 'platform':
            await db.execute(text("UPDATE roles SET name='admin',permissions='[\"HOST_MANAGE_TENANTS\"]'::jsonb WHERE id=:id"), {'id':s.role})
        if boundary == 'other-subject': args['subject'] = 'someone-else'
        if boundary == 'other-tenant': args['tenant_id'] = str(s.other)
        if boundary in ('banned','lifted','foreign-ban','other-kind-ban'):
            await db.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at,lifted_at) VALUES(:id,:tenant,:kind,:user,'fixture ban','fixture',now(),:lifted)"), {'id':uuid.uuid4(),'tenant':s.other if boundary=='foreign-ban' else s.tenant,'kind':'group' if boundary=='other-kind-ban' else 'user','user':s.user,'lifted':datetime.now(UTC) if boundary=='lifted' else None})
    # Empty local cache must not permit a durable ban. No authority in worker memory.
    ban_book().clear()
    reply = await command(s, **args)
    assert reply.status_code == 200, reply.text
    assert reply.json() == ({'user_id':str(s.user)} if boundary in ('direct','group','lifted','foreign-ban','other-kind-ban') else None)


@pytest.mark.parametrize('token', [None,'Bearer wrong','Bearer human-token'])
async def test_host_command_requires_private_auth_service_credential(host_owner, token):
    s=host_owner
    reply=await s.client.post('/api/v1/internal/identity/host-setup',headers={} if token is None else {'Authorization':token},json={'subject':s.subject,'tenant_id':str(s.tenant)})
    assert reply.status_code==401


@pytest.mark.parametrize('body', [{}, {'subject':' '}, {'subject':'x'*513}, {'subject':'valid','tenant_id':None}, {'subject':'valid','tenant_id':'not-a-uuid'}, {'subject':'valid','claims':{'roles':['admin']}}])
async def test_host_command_rejects_missing_or_invalid_binding(host_owner, body):
    s=host_owner
    reply=await s.client.post('/api/v1/internal/identity/host-setup',headers=s.headers,json={'tenant_id':str(s.tenant),**body})
    assert reply.status_code==422
