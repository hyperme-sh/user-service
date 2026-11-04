"""Native transaction and claim boundaries for the closure processor."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from controlplane_db.migrations import upgrade
from controlplane_db.models import IdentityRetirement, User
from panopticon_tests.fixtures.postgres import normalize_sync_sqlalchemy_url
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer
from user_service.closure_jobs import ClosureClaimLost, ClosureJobs
from user_service.models import AccountLifecycle, AccountLifecycleScope


@pytest.fixture(scope="module")
def jobs_url(require_docker):
    with PostgresContainer("postgres:16-alpine") as container:
        url = normalize_sync_sqlalchemy_url(container.get_connection_url())
        upgrade(url)
        yield url


@pytest.fixture
async def jobs(jobs_url):
    engine = create_async_engine(
        jobs_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    clock = [datetime.now(UTC)]
    store = ClosureJobs(
        async_sessionmaker(engine, expire_on_commit=False), clock=lambda: clock[0]
    )
    yield store, clock
    await engine.dispose()


async def test_request_and_retirement_commit_together_and_retries_keep_provenance(jobs):
    store, clock = jobs
    subject = str(uuid.uuid4())
    clock[0] += timedelta(days=365)
    async with store.transaction() as session:
        before = await session.scalar(text("SELECT transaction_timestamp()"))
    first = await store.request(subject, "original-operator", "operator")
    assert first.closed_at is None
    clock[0] += timedelta(hours=1)
    assert await store.request(subject, "another-actor", "self_service") == first
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        marker = await session.get(IdentityRetirement, subject)
        assert row.requested_by == "original-operator" and row.source == "operator"
        after = await session.scalar(text("SELECT transaction_timestamp()"))
        assert before <= row.requested_at == marker.retired_at <= after
        assert row.requested_at < clock[0] - timedelta(days=364)
        assert row.effects == {"processor_version": 1}


async def test_failed_intent_does_not_leave_an_orphan_retirement(jobs, jobs_url):
    store, _ = jobs
    subject = str(uuid.uuid4())
    suffix = uuid.uuid4().hex
    function = "fail_closure_" + suffix
    trigger = "fail_closure_" + suffix
    engine = create_engine(jobs_url)
    with engine.begin() as cx:
        cx.execute(
            text(
                f"CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'planned intent failure'; END $$"
            )
        )
        cx.execute(
            text(
                f"CREATE TRIGGER {trigger} AFTER INSERT ON account_lifecycles FOR EACH ROW EXECUTE FUNCTION {function}()"
            )
        )
    try:
        with pytest.raises(DBAPIError, match="planned intent failure"):
            await store.request(subject, subject, "self_service")
        async with store.transaction() as session:
            assert await session.get(AccountLifecycle, subject) is None
            assert await session.get(IdentityRetirement, subject) is None
    finally:
        with engine.begin() as cx:
            cx.execute(text(f"DROP TRIGGER {trigger} ON account_lifecycles"))
            cx.execute(text(f"DROP FUNCTION {function}()"))
        engine.dispose()


async def test_claims_expire_and_old_worker_cannot_replace_original_receipts(jobs):
    store, clock = jobs
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    claim = await store.claim(subject)
    assert claim.claim_id is not None
    assert await store.claim(subject) is None
    clock[0] += timedelta(seconds=1)
    acknowledged = await store.identity_disabled(claim)
    at = acknowledged.closed_at
    await store.effect(claim, "key_tenants", [])
    with pytest.raises(ValueError, match="cannot be replaced"):
        await store.effect(claim, "key_tenants", [str(uuid.uuid4())])
    await _set_database_time(
        store, subject, claim_until="transaction_timestamp() - interval '1 second'"
    )
    second = await store.claim(subject)
    assert second.claim_id != claim.claim_id
    with pytest.raises(ClosureClaimLost):
        await store.release(claim)
    assert (await store.identity_disabled(second)).closed_at == at
    await store.release(second, error="owner_unavailable")
    assert await store.claim(subject) is None
    await _set_database_time(
        store, subject, retry_at="transaction_timestamp() - interval '1 second'"
    )
    assert await store.claim(subject) is not None


async def test_scope_inventory_is_canonical_and_owner_receipts_are_immutable(jobs):
    store, _ = jobs
    subject = str(uuid.uuid4())
    tenant, identifier = uuid.uuid4(), uuid.uuid4()
    async with store.transaction(tenant) as session:
        await session.execute(
            text("INSERT INTO tenants (id,name,is_active) VALUES (:id,:name,true)"),
            {"id": tenant, "name": str(tenant)},
        )
        session.add(
            User(
                id=identifier,
                tenant_id=tenant,
                keycloak_sub=subject,
                email=subject + "@example.invalid",
                first_name="Private",
                last_name="Person",
                gender="unspecified",
                is_active=True,
            )
        )
    await store.request(subject, subject, "self_service")
    claim = await store.claim(subject)
    with pytest.raises(ValueError, match="disablement must be recorded first"):
        await store.prepare_scope(claim, tenant)
    acknowledged = await store.identity_disabled(claim)
    inventory = await store.prepare_scope(claim, tenant)
    assert inventory == {
        "user_ids": [str(identifier)],
        "effects": {"profile_inventory_complete": True},
    }
    assert await store.prepare_scope(claim, tenant) == inventory
    receipt = {
        "keys": [
            {"id": str(uuid.uuid4()), "fingerprint": "a" * 64, "purpose": "renter"}
        ]
    }
    await store.scope_effect(claim, tenant, "api_keys", receipt)
    with pytest.raises(ValueError, match="cannot be replaced"):
        await store.scope_effect(claim, tenant, "api_keys", {"keys": []})
    async with store.transaction(tenant) as session:
        assert (await session.get(User, identifier)).is_active is False
        scope = await session.get(AccountLifecycleScope, (tenant, subject))
        assert scope.user_ids == [str(identifier)]
        assert scope.effects["api_keys"] == receipt
        assert (
            await session.scalar(
                select(AccountLifecycle.closed_at).where(
                    AccountLifecycle.subject == subject
                )
            )
            == acknowledged.closed_at
        )


async def test_concurrent_intents_share_one_original_retirement(jobs):
    store, _ = jobs
    subject = str(uuid.uuid4())
    first, second = await asyncio.gather(
        store.request(subject, "first-actor", "operator"),
        store.request(subject, "second-actor", "operator"),
    )
    assert first == second
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        marker = await session.get(IdentityRetirement, subject)
        assert row.requested_by in {"first-actor", "second-actor"}
        assert row.requested_at == marker.retired_at


async def _set_database_time(store, subject, **assignments):
    clauses = ", ".join(f"{column} = {expression}" for column, expression in assignments.items())
    async with store.transaction() as session:
        await session.execute(
            text(f"UPDATE account_lifecycles SET {clauses} WHERE subject = :subject"),
            {"subject": subject},
        )


async def test_boolean_and_numeric_receipts_are_not_interchangeable(jobs):
    store, _ = jobs
    subject, tenant = str(uuid.uuid4()), uuid.uuid4()
    async with store.transaction(tenant) as session:
        await session.execute(
            text("INSERT INTO tenants (id,name,is_active) VALUES (:id,:name,true)"),
            {"id": tenant, "name": str(tenant)},
        )
    await store.request(subject, subject, "self_service")
    claim = await store.claim(subject)
    await store.identity_disabled(claim)
    original = {"disabled": True, "flags": [True]}
    await store.effect(claim, "marker", original)
    await store.effect(claim, "marker", {"disabled": True, "flags": [True]})
    with pytest.raises(ValueError, match="cannot be replaced"):
        await store.effect(claim, "marker", {"disabled": 1, "flags": [True]})
    with pytest.raises(ValueError, match="cannot be replaced"):
        await store.effect(claim, "marker", {"disabled": True, "flags": [1]})
    async with store.transaction() as session:
        saved = (await session.get(AccountLifecycle, subject)).effects["marker"]
        assert saved["disabled"] is True and type(saved["disabled"]) is bool
        assert saved["flags"] == [True]
    await store.prepare_scope(claim, tenant)
    await store.scope_effect(claim, tenant, "api_keys", {"complete": True})
    with pytest.raises(ValueError, match="cannot be replaced"):
        await store.scope_effect(claim, tenant, "api_keys", {"complete": 1})
    async with store.transaction(tenant) as session:
        scope = await session.get(AccountLifecycleScope, (tenant, subject))
        assert scope.effects["api_keys"]["complete"] is True


async def test_skewed_process_clock_cannot_reclaim_a_database_lease(jobs):
    store, _ = jobs
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    claim = await store.claim(subject)
    ahead = ClosureJobs(
        store.maker, clock=lambda: datetime.now(UTC) + timedelta(hours=2)
    )
    behind = ClosureJobs(
        store.maker, clock=lambda: datetime.now(UTC) - timedelta(hours=2)
    )
    assert await ahead.claim(subject) is None
    assert await behind.claim(subject) is None
    await ahead.effect(claim, "marker", {"ok": True})
    await store.release(claim, error="owner_unavailable")
    assert await ahead.claim(subject) is None
    await _set_database_time(
        store, subject, retry_at="transaction_timestamp() - interval '1 second'"
    )
    assert await behind.claim(subject) is not None


async def test_platform_profile_inventory_is_durable_without_a_null_tenant(jobs):
    store, _ = jobs
    subject, tenant, platform_id, member_id = (
        str(uuid.uuid4()),
        uuid.uuid4(),
        uuid.uuid4(),
        uuid.uuid4(),
    )
    async with store.transaction(tenant) as session:
        await session.execute(
            text("INSERT INTO tenants (id,name,is_active) VALUES (:id,:name,true)"),
            {"id": tenant, "name": str(tenant)},
        )
        session.add(
            User(
                id=member_id,
                tenant_id=tenant,
                keycloak_sub=subject,
                email=subject + "@member.example.invalid",
                first_name="Tenant",
                last_name="Member",
                gender="unspecified",
                is_active=True,
            )
        )
    async with store.transaction() as session:
        session.add(
            User(
                id=platform_id,
                tenant_id=None,
                keycloak_sub=subject,
                email=subject + "@platform.example.invalid",
                first_name="Platform",
                last_name="Person",
                gender="unspecified",
                is_active=True,
            )
        )
    await store.request(subject, subject, "self_service")
    claim = await store.claim(subject)
    await store.identity_disabled(claim)
    inventory = await store.prepare_scope(claim, None)
    assert inventory == {
        "user_ids": [str(platform_id)],
        "effects": {"profile_inventory_complete": True},
    }
    assert await store.prepare_scope(claim, None) == inventory
    async with store.transaction(tenant) as session:
        assert (await session.get(User, member_id)).is_active is True
    async with store.transaction() as session:
        person = await session.get(User, platform_id)
        row = await session.get(AccountLifecycle, subject)
        scopes = (
            await session.scalars(
                select(AccountLifecycleScope).where(
                    AccountLifecycleScope.subject == subject
                )
            )
        ).all()
        assert person.is_active is False
        assert scopes == []
        assert row.effects["platform_profile"] == {
            "user_ids": [str(platform_id)],
            "profile_inventory_complete": True,
        }
        assert row.financial_hold is False


@pytest.mark.parametrize("version", [None, "1", True, 2])
async def test_legacy_or_unrecognized_jobs_are_never_automatically_claimed(
    jobs, version
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    async with store.transaction() as session:
        # SQL UPDATE intentionally bypasses Python JSON equality (True == 1).
        await session.execute(
            update(AccountLifecycle)
            .where(AccountLifecycle.subject == subject)
            .values(effects={} if version is None else {"processor_version": version})
        )
    assert await store.claim(subject) is None
    with pytest.raises(ValueError, match="explicit reconciliation"):
        await store.request(subject, subject, "self_service")


async def test_closed_transition_requires_every_remembered_receiver(jobs):
    store, clock = jobs
    subject, tenant = str(uuid.uuid4()), uuid.uuid4()
    first, late = uuid.uuid4(), uuid.uuid4()
    async with store.transaction() as session:
        await session.execute(
            text("INSERT INTO tenants(id,name,is_active) VALUES (:t,:n,true)"),
            {"t": tenant, "n": str(tenant)},
        )
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    work = await store.prepare_platform_profile(work)
    tenants = await store.tenants()
    for tid in tenants:
        await store.prepare_scope(work, tid)
        await store.scope_effect(work, tid, "api_keys", {"keys": []})
        await store.scope_effect(
            work,
            tid,
            "hypermesh",
            {
                "model_ids": [],
                "lease_ids": [],
                "tickets_revoked": True,
                "new_selling_disabled": True,
            },
        )
        await store.remember_gateways(work, tid, [first] if tid == tenant else [])
    with pytest.raises(ValueError, match="gateway closure"):
        await store.mark_closed(work, tenants)
    await store.scope_effect(work, tenant, "gateway:" + str(first), {"closed": True})
    remembered = await store.remember_gateways(work, tenant, [late])
    assert set(remembered) == {first, late}
    # Later registry removal cannot silently discard an owner's stored data.
    assert set(await store.remember_gateways(work, tenant, [])) == {first, late}
    with pytest.raises(ValueError, match="gateway closure"):
        await store.mark_closed(work, tenants)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "closing" and "scope_discovery" not in row.effects
    await store.scope_effect(work, tenant, "gateway:" + str(late), {"closed": True})
    with pytest.raises(ValueError, match="Tenant registry changed"):
        await store.mark_closed(work, [])
    closed = await store.mark_closed(work, tenants)
    assert closed.state == "closed" and closed.effects["scope_discovery"] is True
    assert closed.claim_id is None
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.retry_at == closed.closed_at + timedelta(days=89)
        assert row.claim_id is row.claim_until is None
        assert row.last_error == "deadline_pending"
    clock[0] += timedelta(seconds=61)
    assert await store.claim(subject) is None
    await _set_database_time(
        store, subject, retry_at="transaction_timestamp() - interval '1 second'"
    )
    assert (await store.claim(subject)).state == "closed"


async def test_registry_pages_renew_the_native_fenced_claim(jobs, monkeypatch):
    import controlplane_tenancy.tenant_registry as registry

    store, clock = jobs
    await simulated_database_clock(store, clock, monkeypatch)
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    identifiers = [uuid.UUID(int=i + 1) for i in range(2001)]
    calls = []

    async def page(session, *, after, limit):
        calls.append(after)
        clock[0] += timedelta(seconds=40)
        offset = 0 if after is None else identifiers.index(after) + 1
        return identifiers[offset : offset + limit]

    monkeypatch.setattr(registry, "tenant_ids_page", page)
    assert await store.tenants(work) == identifiers
    assert len(calls) == 3
    # The 120-second scan still owns the current claim, not an expired token.
    await store.heartbeat(work)
    clock[0] += timedelta(seconds=61)
    replacement = await store.claim(subject)
    assert replacement.claim_id != work.claim_id
    with pytest.raises(ClosureClaimLost):
        await store.tenants(work)
    assert len(calls) == 3


async def test_disable_clock_ignores_skew_between_replicas(jobs):
    store, clock = jobs
    subject = str(uuid.uuid4())
    clock[0] += timedelta(days=365)
    await store.request(subject, subject, "self_service")
    claim = await store.claim(subject)
    # The second replica's local clock is behind the original requester.
    clock[0] -= timedelta(days=730)
    async with store.transaction() as session:
        before = await session.scalar(text("SELECT transaction_timestamp()"))
    acknowledged = await store.identity_disabled(claim)
    async with store.transaction() as session:
        marker = await session.get(IdentityRetirement, subject)
        after = await session.scalar(text("SELECT transaction_timestamp()"))
        assert marker.retired_at <= before <= acknowledged.closed_at <= after
    assert (await store.identity_disabled(claim)).closed_at == acknowledged.closed_at


async def simulated_database_clock(store, clock, monkeypatch):
    """Advance database-time reads for bounded-latency tests without real sleeps.

    Native clock-source and replica-skew tests above do not use this helper.
    Claim ownership and renewal still use the real PostgreSQL row transactions.
    """
    async with store.transaction() as session:
        clock[0] = await store._database_now(session)

    async def now(session):
        return clock[0]

    monkeypatch.setattr(store, "_database_now", now)


async def test_retirement_without_original_lifecycle_cannot_mint_empty_inventory(jobs):
    store, _ = jobs
    subject = str(uuid.uuid4())
    async with store.transaction() as session:
        original = await session.scalar(text('SELECT transaction_timestamp()'))
        session.add(IdentityRetirement(subject=subject, retired_at=original))
    with pytest.raises(ValueError, match='Legacy closure requires explicit reconciliation'):
        await store.request(subject, subject, 'self_service')
    async with store.transaction() as session:
        assert await session.get(AccountLifecycle, subject) is None
        assert (await session.get(IdentityRetirement, subject)).retired_at == original
