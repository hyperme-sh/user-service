"""Read-only ban owner predicates preserve tenant scope and caller transactions."""
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from operator_ban_store import active_ban, subject_banned_sync


@pytest_asyncio.fixture
async def ban_owner(migrated_postgres, db_async_url):
    engine = create_engine(migrated_postgres)
    async_engine = create_async_engine(db_async_url)
    ta, tb, user, group, device, lifted = [uuid.uuid4() for _ in range(6)]
    with engine.begin() as connection:
        for tenant in [ta, tb]:
            connection.execute(text("INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)"),
                               {"id": tenant, "name": str(tenant)})
        for tenant, kind, subject, lift in [(ta,'user',user,None), (ta,'group',group,None),
                (ta,'device',device,None), (ta,'user',lifted,datetime.now(UTC)), (tb,'user',lifted,None)]:
            connection.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at,lifted_at) VALUES(:id,:tenant,:kind,:subject,'test','test',now(),:lift)"),
                {"id": uuid.uuid4(), "tenant": tenant, "kind": kind, "subject": subject, "lift": lift})
    try:
        yield engine, async_sessionmaker(async_engine, expire_on_commit=False), ta, tb, user, group, device, lifted
    finally:
        await async_engine.dispose()
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM tenants WHERE id IN (:a,:b)"), {"a": ta, "b": tb})
        engine.dispose()


@pytest.mark.asyncio
async def test_async_ban_checks_scope_subjects_active_rows_and_uncommitted_state(ban_owner):
    _, maker, ta, tb, user, group, device, lifted = ban_owner
    async with maker() as caller, maker() as observer:
        assert await active_ban(caller, ta, users=(user,))
        assert await active_ban(caller, ta, groups=(group,))
        assert await active_ban(caller, ta, devices=(device,))
        assert not await active_ban(caller, tb, users=(user,), groups=(group,), devices=(device,))
        assert not await active_ban(caller, ta, users=(lifted,))
        assert not await active_ban(caller, ta, devices=(user,))
        assert not await active_ban(caller, ta)
        pending = uuid.uuid4()
        await caller.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,'user',:subject,'test','test',now())"),
            {"id": uuid.uuid4(), "tenant": ta, "subject": pending})
        assert await active_ban(caller, ta, users=(pending,))
        assert not await active_ban(observer, ta, users=(pending,))
        await caller.rollback()
        assert not await active_ban(observer, ta, users=(pending,))


@pytest.mark.asyncio
async def test_sync_and_async_owner_do_not_widen_rls(ban_owner, rls_isolation_role_ready):
    engine, maker, ta, tb, user, _, _, lifted = ban_owner
    with engine.begin() as connection:
        connection.execute(text("GRANT SELECT ON operator_bans TO spanopticon_rls_tester"))
    with engine.connect() as connection:
        assert subject_banned_sync(connection, ta, 'user', user)
        assert not subject_banned_sync(connection, ta, 'user', lifted)
        connection.execute(text("SET LOCAL ROLE spanopticon_rls_tester"))
        connection.execute(text("SELECT set_config('app.current_tenant_id', :tid, true)"), {"tid": str(ta)})
        assert subject_banned_sync(connection, ta, 'user', user)
        assert not subject_banned_sync(connection, tb, 'user', lifted)
    async with maker() as session:
        await session.execute(text("SET LOCAL ROLE spanopticon_rls_tester"))
        await session.execute(text("SELECT set_config('app.current_tenant_id', :tid, true)"), {"tid": str(ta)})
        assert await active_ban(session, ta, users=(user,))
        assert not await active_ban(session, tb, users=(lifted,))
