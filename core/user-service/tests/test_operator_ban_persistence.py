"""Durable endpoint behavior across independent sessions and empty local books."""
import uuid
import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from api.domain.operator.bans import ban_book
from user_service.interfaces.api import operator_routes as routes

# Owning-service tests share the service's disposable migrated PostgreSQL.
# The separately packaged contract retains its independent migration fixture.
@pytest.fixture(scope="session")
def migrated_postgres(migrated_sync_url):
    return migrated_sync_url

@pytest.mark.asyncio
async def test_endpoints_use_durable_tenant_records_after_restart(migrated_postgres, monkeypatch):
    from sqlalchemy.engine import make_url
    engine = create_async_engine(make_url(migrated_postgres).set(drivername='postgresql+asyncpg'))
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant, other, subject = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    claims = {'tenant_id': str(tenant), 'sub': 'operator-test'}
    monkeypatch.setattr(routes, 'require_support', lambda request: claims)
    try:
        async with maker() as session:
            for tid in (tenant, other):
                await session.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'), {'id':tid,'name':str(tid)})
            monkeypatch.setattr(routes, '_db', lambda: session)
            created = await routes.create_ban(None, routes.BanBody(subject_kind='user',subject_id=subject,reason='test'))
            await session.commit()
        ban_book().clear()  # Different worker/restarted process has no local history.
        async with maker() as session:
            monkeypatch.setattr(routes, '_db', lambda: session)
            rows = await routes.list_bans(None)
            assert [row['id'] for row in rows['items']] == [created['id']]
            assert (await routes.list_bans(None, subject_kind='device'))['items'] == []
            claims['tenant_id'] = str(other)
            assert (await routes.list_bans(None))['items'] == []
            with pytest.raises(HTTPException) as exc:
                await routes.lift_ban(None, uuid.UUID(created['id']), routes.LiftBody(reason='wrong tenant'))
            assert exc.value.status_code == 404
            claims['tenant_id'] = str(tenant)
            lifted = await routes.lift_ban(None, uuid.UUID(created['id']), routes.LiftBody(reason=' resolved '))
            assert lifted['active'] is False and lifted['lift_reason'] == 'resolved'
            await session.rollback()  # Helper must not commit the caller transaction.
        async with maker() as session:
            monkeypatch.setattr(routes, '_db', lambda: session)
            assert (await routes.list_bans(None))['items'][0]['active'] is True
            await routes.lift_ban(None, uuid.UUID(created['id']), routes.LiftBody(reason='resolved'))
            await session.commit()
        async with maker() as session:
            monkeypatch.setattr(routes, '_db', lambda: session)
            assert (await routes.list_bans(None))['items'][0]['active'] is False
            with pytest.raises(HTTPException) as exc:
                await routes.lift_ban(None, uuid.UUID(created['id']), routes.LiftBody(reason='again'))
            assert exc.value.status_code == 404
            await routes.create_ban(None, routes.BanBody(subject_kind='user',subject_id=subject,reason='new ban'))
            with pytest.raises(HTTPException) as exc:
                await routes.create_ban(None, routes.BanBody(subject_kind='user',subject_id=subject,reason='duplicate'))
            assert exc.value.status_code == 409
    finally:
        ban_book().clear()
        await engine.dispose()

@pytest.mark.asyncio
async def test_portal_group_grants_follow_durable_bans(migrated_postgres, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from sqlalchemy.engine import make_url
    from user_service.interfaces.api import routes as portal
    from user_service.infrastructure.operator_store import lift_ban
    engine = create_async_engine(make_url(migrated_postgres).set(drivername='postgresql+asyncpg'))
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant, other, group, ban = [uuid.uuid4() for _ in range(4)]
    monkeypatch.setattr(portal, '_lookup_actor_user', AsyncMock(return_value=SimpleNamespace(id=uuid.uuid4(),role_id=None)))
    monkeypatch.setattr(portal.SqlMembershipRepository, 'groups_for_user', AsyncMock(return_value=[SimpleNamespace(id=group,name='ir_export')]))
    me = SimpleNamespace(roles=[], groups=[])
    try:
        async with maker() as session:
            for tid in (tenant, other):
                await session.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'), {'id':tid,'name':str(tid)})
            await session.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,'group',:subject,'test','test',now())"), {'id':ban,'tenant':tenant,'subject':group})
            await session.commit()
        ban_book().clear()
        async with maker() as session:
            assert not (await portal.actor_portal_controls(session, tenant, me)).can_export_ir_receipts
            assert (await portal.actor_portal_controls(session, other, me)).can_export_ir_receipts
            await lift_ban(session, tenant, ban, lift_reason='resolved', lifted_by='test')
            assert (await portal.actor_portal_controls(session, tenant, me)).can_export_ir_receipts
            await session.rollback()
        async with maker() as session:
            assert not (await portal.actor_portal_controls(session, tenant, me)).can_export_ir_receipts
            await lift_ban(session, tenant, ban, lift_reason='resolved', lifted_by='test')
            await session.commit()
        async with maker() as session:
            assert (await portal.actor_portal_controls(session, tenant, me)).can_export_ir_receipts
    finally:
        ban_book().clear()
        await engine.dispose()
