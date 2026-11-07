"""Tenant activity gates both membership and platform override grants."""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from auth_service.schemas import AuthMeResponse
from controlplane_api.permissions import Permission
from user_service.identity_tenant_switch import authorize_tenant_switch


@pytest.mark.parametrize('path', ['membership', 'platform_override'])
@pytest.mark.parametrize('active', [False, True])
async def test_switch_requires_active_target_for_every_grant_path(migrated_sync_url, path, active):
    engine = create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg'))
    tenant, role, actor = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    subject = 'tenant-switch-' + uuid.uuid4().hex
    email = str(actor) + '@example.com'
    member_scope = tenant if path == 'membership' else None
    role_name = 'fixture-' + role.hex
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await connection.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,:active)'),
                                     {'id': tenant, 'name': str(tenant), 'active': active})
            await connection.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,:name,jsonb_build_array(CAST(:permission AS text)))"),
                                     {'id': role, 'tenant': member_scope, 'name': role_name,
                                      'permission': Permission.HOST_MANAGE_TENANTS.value})
            await connection.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id) VALUES(:id,:tenant,:sub,:email,'Switch','Fixture','unspecified',true,:role)"),
                                     {'id': actor, 'tenant': member_scope, 'sub': subject, 'email': email, 'role': role})
        async with maker() as session:
            grant = await authorize_tenant_switch(AuthMeResponse(sub=subject, email=email), tenant, session=session)
        if active:
            assert grant is not None
            assert grant.role_name == role_name
            assert grant.user_id == actor
        else:
            assert grant is None
    finally:
        async with engine.begin() as connection:
            await connection.execute(text('DELETE FROM users WHERE id=:id'), {'id': actor})
            await connection.execute(text('DELETE FROM roles WHERE id=:id'), {'id': role})
            await connection.execute(text('DELETE FROM tenants WHERE id=:id'), {'id': tenant})
        await engine.dispose()
