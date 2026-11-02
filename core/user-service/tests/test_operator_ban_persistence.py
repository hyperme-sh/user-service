"""Durable endpoint behavior across independent sessions and empty local books."""
import uuid
from pathlib import Path
import importlib.util
import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from api.domain.operator.bans import ban_book
from user_service.interfaces.api import operator_routes as routes

# Reuse the isolated migrated database fixture from the contract tests.
spec = importlib.util.spec_from_file_location('ban_database_fixtures', Path(__file__).parents[1] / 'contracts/tests/conftest.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
migrated_postgres = fixtures.migrated_postgres

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
