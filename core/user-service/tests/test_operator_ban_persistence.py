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


@pytest.mark.asyncio
async def test_concurrent_lifts_have_one_committed_winner(migrated_postgres):
    import asyncio
    from api.domain.operator.bans import BanBook, BanError
    from sqlalchemy.engine import make_url
    from user_service.infrastructure.operator_store import insert_ban, lift_ban, list_bans

    engine = create_async_engine(make_url(migrated_postgres).set(drivername='postgresql+asyncpg'))
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant = uuid.uuid4()
    row = BanBook().ban(tenant_id=tenant, subject_kind='device', subject_id=uuid.uuid4(),
                        reason='concurrent lift regression', created_by='test')
    try:
        async with maker() as session:
            await session.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'),
                                  {'id': tenant, 'name': str(tenant)})
            await insert_ban(session, row)
            await session.commit()

        async def lift(actor):
            async with maker() as session:
                result = await lift_ban(session, tenant, row.id, lift_reason='resolved', lifted_by=actor)
                await session.commit()
                return result

        results = await asyncio.gather(lift('first'), lift('second'), return_exceptions=True)
        assert sum(isinstance(result, BanError) for result in results) == 1
        winners = [result for result in results if not isinstance(result, Exception)]
        assert len(winners) == 1
        async with maker() as session:
            stored = (await list_bans(session, tenant))[0]
            assert not stored.active
            assert stored.lifted_by == winners[0].lifted_by
            assert stored.lifted_at == winners[0].lifted_at
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_directory_and_soft_delete_use_durable_bans(migrated_postgres, monkeypatch):
    from controlplane_db.models import User
    from sqlalchemy.engine import make_url
    engine = create_async_engine(make_url(migrated_postgres).set(drivername='postgresql+asyncpg'))
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant, first, second = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    claims = {'tenant_id': str(tenant), 'sub': 'operator-directory-test'}
    monkeypatch.setattr(routes, 'require_support', lambda request: claims)
    try:
        async with maker() as session:
            await session.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'),
                                  {'id': tenant, 'name': str(tenant)})
            for user_id in (first, second):
                session.add(User(id=user_id, tenant_id=tenant, email=str(user_id) + '@example.com',
                    first_name='Directory', last_name='Test', gender='unspecified', is_active=True))
            await session.flush()
            monkeypatch.setattr(routes, '_db', lambda: session)
            bans = [await routes.create_ban(None, routes.BanBody(subject_kind='user',
                subject_id=user_id, reason='directory regression')) for user_id in (first, second)]
            await session.commit()
        ban_book().clear()
        async with maker() as session:
            monkeypatch.setattr(routes, '_db', lambda: session)
            listed = await routes.directory_users(None, q=None, limit=50, offset=0)
            assert {row['active_ban']['id'] for row in listed['items']} == {ban['id'] for ban in bans}
            deleted = await routes.soft_delete_user(None, first, routes.ReasonBody(reason='remove profile'))
            assert deleted['banned'] is True
            await routes.lift_ban(None, uuid.UUID(bans[1]['id']), routes.LiftBody(reason='resolved'))
            await session.commit()
        async with maker() as session:
            monkeypatch.setattr(routes, '_db', lambda: session)
            listed = await routes.directory_users(None, q=None, limit=50, offset=0)
            assert len(listed['items']) == 1
            assert listed['items'][0]['active_ban'] is None
            deleted = await routes.soft_delete_user(None, second, routes.ReasonBody(reason='remove profile'))
            assert deleted['banned'] is False
    finally:
        ban_book().clear()
        await engine.dispose()
