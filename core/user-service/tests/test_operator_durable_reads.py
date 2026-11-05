"""Console read behavior across committed transactions and worker restarts."""
from datetime import UTC, datetime
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.domain.operator.audit import operator_audit
from api.domain.operator.bans import ban_book
from user_service.interfaces.api import operator_routes as routes


@pytest.fixture
async def console_store(migrated_sync_url, monkeypatch):
    engine = create_async_engine(make_url(migrated_sync_url).set(drivername="postgresql+asyncpg"))
    s = SimpleNamespace(
        tenant=uuid.uuid4(), other=uuid.uuid4(), user=uuid.uuid4(),
        second=uuid.uuid4(), foreign_user=uuid.uuid4(), role=uuid.uuid4(),
        maker=async_sessionmaker(engine, expire_on_commit=False),
    )
    s.claims = {"tenant_id": str(s.tenant), "sub": "console-operator",
                "permissions": ["operator:console", "operator:support"]}
    monkeypatch.setattr(routes, "require_console", lambda request: s.claims)
    monkeypatch.setattr(routes, "require_support", lambda request: s.claims)
    s.bind = lambda session: monkeypatch.setattr(routes, "_db", lambda: session)
    operator_audit().clear()
    ban_book().clear()
    async with s.maker() as session:
        for tenant in (s.tenant, s.other):
            await session.execute(text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)"),
                                  {"id": tenant, "name": str(tenant)})
        await session.execute(text("INSERT INTO roles (id, tenant_id, name, permissions) VALUES (:id, :tenant, 'member', '[]'::jsonb)"),
                              {"id": s.role, "tenant": s.tenant})
        for user, tenant in ((s.user, s.tenant), (s.second, s.tenant), (s.foreign_user, s.other)):
            await session.execute(text("INSERT INTO users (id, tenant_id, email, first_name, last_name, gender, is_active) "
                                       "VALUES (:id, :tenant, :email, 'Console', 'Target', 'unspecified', true)"),
                                  {"id": user, "tenant": tenant, "email": f"{user}@example.com"})
        await session.commit()
    try:
        yield s
    finally:
        async with s.maker() as session:
            for table in ("operator_audit", "operator_bans", "users", "roles"):
                await session.execute(text(f"DELETE FROM {table} WHERE tenant_id IN (:a, :b)"),
                                      {"a": s.tenant, "b": s.other})
            await session.execute(text("DELETE FROM tenants WHERE id IN (:a, :b)"), {"a": s.tenant, "b": s.other})
            await session.commit()
        operator_audit().clear()
        ban_book().clear()
        await engine.dispose()


async def directory():
    return await routes.directory_users(None, q=None, limit=50, offset=0)


async def test_directory_reads_committed_bans_after_restart_and_lift(console_store):
    s = console_store
    async with s.maker() as session:
        s.bind(session)
        created = await routes.create_ban(None, routes.BanBody(
            subject_kind="user", subject_id=s.user, reason="durable user ban"))
        await routes.create_ban(None, routes.BanBody(
            subject_kind="group", subject_id=s.second, reason="different subject kind"))
        s.claims["tenant_id"] = str(s.other)
        await routes.create_ban(None, routes.BanBody(
            subject_kind="user", subject_id=s.user, reason="different tenant"))
        await session.commit()
    s.claims["tenant_id"] = str(s.tenant)
    ban_book().clear()
    # A stale local cache must neither mask the durable ban nor fabricate one.
    ban_book().ban(tenant_id=s.tenant, subject_kind="user", subject_id=s.second,
                   reason="stale local entry", created_by="old-worker")
    async with s.maker() as session:
        s.bind(session)
        page = await directory()
        users = {row["id"]: row for row in page["items"]}
        assert set(users) == {str(s.user), str(s.second)}
        assert page["total"] == 2
        assert users[str(s.user)]["active_ban"]["id"] == created["id"]
        assert users[str(s.second)]["active_ban"] is None
        assert users[str(s.user)]["active_ban"]["reason"] == "durable user ban"
        # Reads must not commit caller-owned writes.
        await routes.lift_ban(None, uuid.UUID(created["id"]), routes.LiftBody(reason="not committed"))
        assert next(row for row in (await directory())["items"] if row["id"] == str(s.user))["active_ban"] is None
        await session.rollback()
    async with s.maker() as session:
        s.bind(session)
        assert next(row for row in (await directory())["items"] if row["id"] == str(s.user))["active_ban"] is not None
        await routes.lift_ban(None, uuid.UUID(created["id"]), routes.LiftBody(reason="resolved"))
        await session.commit()
    ban_book().clear()
    ban_book().ban(tenant_id=s.tenant, subject_kind="user", subject_id=s.user,
                   reason="stale after lift", created_by="old-worker")
    async with s.maker() as session:
        s.bind(session)
        assert all(row["active_ban"] is None for row in (await directory())["items"])
        s.claims["tenant_id"] = str(s.other)
        foreign = await directory()
        assert [row["id"] for row in foreign["items"]] == [str(s.foreign_user)]
        assert foreign["items"][0]["active_ban"] is None


async def test_audit_reads_committed_ban_lift_and_role_after_restart(console_store):
    s = console_store
    async with s.maker() as session:
        s.bind(session)
        ban = await routes.create_ban(None, routes.BanBody(subject_kind="user", subject_id=s.user, reason="abuse"))
        await routes.lift_ban(None, uuid.UUID(ban["id"]), routes.LiftBody(reason="reviewed"))
        await routes.edit_role(None, s.user, routes.RoleBody(role_id=s.role, reason="membership"))
        await session.commit()
    operator_audit().clear()
    async with s.maker() as session:
        s.bind(session)
        rows = (await routes.list_audit(None))["items"]
        assert [row["action"] for row in rows] == ["role", "lift_ban", "ban"]
        assert [row["reason"] for row in rows] == ["membership", "reviewed", "abuse"]
        assert rows[0]["detail"] == {"role_id": str(s.role)}
        assert all(row["actor"] == "console-operator" and row["target_id"] == str(s.user) for row in rows)
        assert set(rows[0]) == {"id", "tenant_id", "actor", "action", "target_kind", "target_id", "reason", "created_at", "detail"}
        s.claims["tenant_id"] = str(s.other)
        assert (await routes.list_audit(None))["items"] == []


@pytest.mark.parametrize("commit", [False, True])
async def test_audit_obeys_caller_transaction_visibility(console_store, commit):
    s = console_store
    async with s.maker() as writer:
        s.bind(writer)
        await routes.edit_role(None, s.user, routes.RoleBody(role_id=s.role, reason="transaction test"))
        own = (await routes.list_audit(None))["items"]
        assert [row["action"] for row in own] == ["role"]
        async with s.maker() as observer:
            s.bind(observer)
            assert (await routes.list_audit(None))["items"] == []
        await (writer.commit() if commit else writer.rollback())
    operator_audit().clear()
    async with s.maker() as observer:
        s.bind(observer)
        assert (await routes.list_audit(None))["items"] == (own if commit else [])
        role = await observer.scalar(text("SELECT role_id FROM users WHERE id=:id"), {"id": s.user})
        assert role == (s.role if commit else None)


async def test_audit_pagination_orders_timestamp_ties_by_id(console_store):
    s = console_store
    instant = datetime(2026, 1, 1, tzinfo=UTC)
    base = uuid.uuid4().int & ~255
    async with s.maker() as session:
        for tenant in (s.tenant, s.other):
            for i in range(5):
                await session.execute(text("INSERT INTO operator_audit (id, tenant_id, actor, action, target_kind, target_id, reason, created_at) "
                                           "VALUES (:id, :tenant, 'actor', 'role', 'user', 'target', 'reason', :instant)"),
                                      {"id": uuid.UUID(int=base + i + 1 + (100 if tenant == s.other else 0)), "tenant": tenant, "instant": instant})
        await session.commit()
    operator_audit().clear()
    async with s.maker() as session:
        s.bind(session)
        first = await routes.list_audit(None, limit=2, offset=0)
        second = await routes.list_audit(None, limit=2, offset=2)
        assert first["limit"] == 2 and second["offset"] == 2
        assert [row["id"] for row in first["items"] + second["items"]] == [str(uuid.UUID(int=base + i)) for i in (5, 4, 3, 2)]
        assert (await routes.list_audit(None, limit=2, offset=5))["items"] == []


@pytest.mark.parametrize("query", ["no-such-user", "x" * 256])
async def test_empty_directory_does_not_promote_local_lookup_diagnostics(console_store, query):
    s = console_store
    async with s.maker() as session:
        s.bind(session)
        page = await routes.directory_users(None, q=query, limit=50, offset=0)
        assert page["items"] == [] and page["total"] == 0
        await session.commit()
    operator_audit().clear()
    async with s.maker() as session:
        s.bind(session)
        assert (await routes.list_audit(None))["items"] == []


async def test_no_session_reads_keep_local_audit_and_empty_directory(monkeypatch):
    tenant, other = uuid.uuid4(), uuid.uuid4()
    claims = {"tenant_id": str(tenant), "permissions": ["operator:console", "operator:support"]}
    monkeypatch.setattr(routes, "require_console", lambda request: claims)
    monkeypatch.setattr(routes, "require_support", lambda request: claims)
    monkeypatch.setattr(routes, "_db", lambda: None)
    operator_audit().clear()
    try:
        local = [operator_audit().append(tenant_id=tenant, actor="local", action="ban", target_kind="user",
                                        target_id="subject", reason=str(i)) for i in range(3)]
        operator_audit().append(tenant_id=other, actor="foreign", action="ban", target_kind="user",
                                target_id="subject", reason="not visible")
        rows = (await routes.list_audit(None, limit=1, offset=1))["items"]
        assert rows == [local[1].public()]
        assert (await directory())["items"] == []
    finally:
        operator_audit().clear()
