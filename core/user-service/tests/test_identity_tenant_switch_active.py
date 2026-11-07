"""Tenant activity gates both membership and platform override grants."""
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_service.schemas import AuthMeResponse
from controlplane_api.permissions import Permission
from user_service.identity_tenant_switch import authorize_tenant_switch


@pytest.fixture(scope='module')
def owner_switch_schema(postgres_sync_url):
    from pathlib import Path
    import hashlib
    from sqlalchemy import create_engine
    from controlplane_events.owner_schema import migrate
    name = 'switch_owner_' + uuid.uuid4().hex
    password = uuid.uuid4().hex
    admin = create_engine(postgres_sync_url)
    with admin.begin() as db:
        db.execute(text(f'CREATE ROLE "{name}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
        db.execute(text(f'CREATE SCHEMA "{name}" AUTHORIZATION "{name}"'))
        db.execute(text(f'ALTER ROLE "{name}" SET search_path TO "{name}"'))
    owner = create_engine(make_url(postgres_sync_url).set(username=name,password=password))
    try:
        ddl = Path(__file__).with_name('fixtures').joinpath('owner-schema.sql').read_bytes()
        assert hashlib.sha256(ddl).hexdigest() == 'b1e0e5c3ddc1688a442c6c82b20af66951a1edff8eeaa8b330bfb5e916143fe4'
        migrate(owner, revision='0001_owner_schema', ddl=ddl.decode())
        yield postgres_sync_url, name
    finally:
        owner.dispose()
        with admin.begin() as db:
            db.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
            db.execute(text(f'DROP OWNED BY "{name}"'))
            db.execute(text(f'DROP ROLE "{name}"'))
        admin.dispose()


@pytest.mark.parametrize('path', ['membership', 'platform_override'])
@pytest.mark.parametrize('active', [False, True])
@pytest.mark.parametrize('binding', ['subject', 'legacy-email'])
@pytest.mark.parametrize('ban', ['absent', 'active', 'lifted', 'foreign', 'other-kind'])
async def test_switch_requires_active_target_for_every_grant_path(owner_switch_schema, path, active, binding, ban):
    migrated_sync_url, schema = owner_switch_schema
    engine = create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg'), connect_args={'server_settings':{'search_path':schema}})
    tenant, role, actor, other = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    reader = "switch_reader_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    restricted = create_async_engine(make_url(migrated_sync_url).set(drivername="postgresql+asyncpg", username=reader, password=password))
    subject = 'tenant-switch-' + uuid.uuid4().hex
    email = str(actor) + '@example.com'
    member_scope = tenant if path == 'membership' else None
    role_name = 'fixture-' + role.hex
    maker = async_sessionmaker(restricted, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await connection.execute(text(f'CREATE ROLE "{reader}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
            await connection.execute(text(f'ALTER ROLE "{reader}" SET search_path TO "{schema}"'))
            await connection.execute(text(f'GRANT USAGE ON SCHEMA "{schema}" TO "{reader}"'))
            await connection.execute(text(f'GRANT SELECT ON tenants,users,roles,groups,user_group_memberships,operator_bans TO "{reader}"'))
            await connection.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'), {'id':other,'name':str(other)})
            await connection.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,:active)'),
                                     {'id': tenant, 'name': str(tenant), 'active': active})
            await connection.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,:name,jsonb_build_array(CAST(:permission AS text)))"),
                                     {'id': role, 'tenant': member_scope, 'name': role_name,
                                      'permission': Permission.HOST_MANAGE_TENANTS.value})
            await connection.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id) VALUES(:id,:tenant,:sub,:email,'Switch','Fixture','unspecified',true,:role)"),
                                     {'id': actor, 'tenant': member_scope, 'sub': subject if binding == 'subject' else None, 'email': email, 'role': role})
        async with engine.begin() as connection:
            if ban != 'absent':
                await connection.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at,lifted_at) VALUES(:id,:tenant,:kind,:actor,'fixture','fixture',now(),:lifted)"), {'id':uuid.uuid4(),'tenant':other if ban == 'foreign' else tenant,'kind':'group' if ban == 'other-kind' else 'user','actor':actor,'lifted':datetime.now(UTC) if ban == 'lifted' else None})
        async with maker() as session:
            grant = await authorize_tenant_switch(AuthMeResponse(sub=subject, email=email), tenant, session=session)
        if active and ban != "active":
            assert grant is not None
            assert grant.role_name == role_name
            assert grant.user_id == actor
        else:
            assert grant is None
    finally:
        await restricted.dispose()
        async with engine.begin() as connection:
            await connection.execute(text('DELETE FROM operator_bans WHERE tenant_id IN (:a,:b)'), {'a':tenant,'b':other})
            await connection.execute(text('DELETE FROM users WHERE id=:id'), {'id': actor})
            await connection.execute(text('DELETE FROM roles WHERE id=:id'), {'id': role})
            await connection.execute(text('DELETE FROM tenants WHERE id=:id'), {'id': tenant})
            await connection.execute(text('DELETE FROM tenants WHERE id=:id'), {'id':other})
            await connection.execute(text(f'DROP OWNED BY "{reader}"'))
            await connection.execute(text(f'DROP ROLE "{reader}"'))
        await engine.dispose()
