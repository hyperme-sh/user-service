"""Native financial permits serialize accepted holds without HTTP transactions."""

import asyncio
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414

CALL = text("SELECT public.account_lock_financial_erasure(:s,:at,:t)")


async def closed_account(store):
    subject = str(uuid.uuid4())
    tenant = uuid.uuid4()
    async with store.transaction() as session:
        await session.execute(
            text("INSERT INTO tenants(id,name,is_active) VALUES (:t,:n,false)"),
            {"t": tenant, "n": str(tenant)},
        )
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    work = await store.prepare_platform_profile(work)
    tenants = await store.tenants(work)
    for tenant in tenants:
        await store.prepare_scope(work, tenant)
        await store.scope_effect(work, tenant, "api_keys", {"keys": []})
        await store.scope_effect(
            work,
            tenant,
            "hypermesh",
            {
                "model_ids": [],
                "lease_ids": [],
                "tickets_revoked": True,
                "new_selling_disabled": True,
            },
        )
        await store.remember_gateways(work, tenant, [])
    return await store.mark_closed(work, tenants)


async def test_native_guard_requires_original_closed_scope_and_unheld_account(jobs):
    store, _ = jobs
    work = await closed_account(store)
    async with store.transaction() as session:
        await session.execute(
            CALL, {"s": work.subject, "at": work.closed_at, "t": None}
        )
    for tenant in await store.tenants():
        async with store.transaction() as session:
            await session.execute(
                CALL, {"s": work.subject, "at": work.closed_at, "t": tenant}
            )
    for subject, at, tenant in (
        (work.subject, work.closed_at + timedelta(seconds=1), None),
        (work.subject, work.closed_at, uuid.uuid4()),
        ("another-account", work.closed_at, None),
    ):
        with pytest.raises(DBAPIError, match="Financial erasure authority unavailable"):
            async with store.transaction() as session:
                await session.execute(CALL, {"s": subject, "at": at, "t": tenant})
    async with store.transaction() as session:
        await session.execute(
            text(
                "UPDATE account_lifecycles SET financial_hold=true,hold_reference='explicit' WHERE subject=:s"
            ),
            {"s": work.subject},
        )
    with pytest.raises(DBAPIError, match="Financial erasure authority unavailable"):
        async with store.transaction() as session:
            await session.execute(
                CALL, {"s": work.subject, "at": work.closed_at, "t": None}
            )
    # Only an explicit committed release removes the preservation fence.
    async with store.transaction() as session:
        await session.execute(
            text(
                "UPDATE account_lifecycles SET financial_hold=false,hold_reference=NULL WHERE subject=:s"
            ),
            {"s": work.subject},
        )
    async with store.transaction() as session:
        await session.execute(
            CALL, {"s": work.subject, "at": work.closed_at, "t": None}
        )


async def test_hold_cannot_commit_during_a_native_financial_erasure_transaction(jobs):
    store, _ = jobs
    work = await closed_account(store)
    started = asyncio.Future()

    async def accept_hold():
        async with store.transaction() as session:
            pid = await session.scalar(text("SELECT pg_backend_pid()"))
            started.set_result(pid)
            await session.execute(
                text(
                    "UPDATE account_lifecycles SET financial_hold=true,hold_reference='explicit' WHERE subject=:s"
                ),
                {"s": work.subject},
            )

    task = None
    try:
        async with store.transaction() as session:
            await session.execute(
                CALL, {"s": work.subject, "at": work.closed_at, "t": None}
            )
            task = asyncio.create_task(accept_hold())
            pid = await started
            async with asyncio.timeout(5):
                while True:
                    async with store.transaction() as observer:
                        waiting = await observer.scalar(
                            text(
                                "SELECT wait_event_type FROM pg_stat_activity WHERE pid=:pid"
                            ),
                            {"pid": pid},
                        )
                    if waiting == "Lock":
                        break
                    await asyncio.sleep(0.01)
            assert not task.done()
            assert (
                await session.scalar(
                    text(
                        "SELECT financial_hold FROM account_lifecycles WHERE subject=:s"
                    ),
                    {"s": work.subject},
                )
                is False
            )
        # An accepted hold linearizes after the earlier erasure transaction.
        await task
        with pytest.raises(DBAPIError, match="Financial erasure authority unavailable"):
            async with store.transaction() as session:
                await session.execute(
                    CALL, {"s": work.subject, "at": work.closed_at, "t": None}
                )
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_minimal_worker_role_can_check_a_permit_without_reading_root_rows(jobs):
    store, _ = jobs
    work = await closed_account(store)
    role = "financial_guard_" + uuid.uuid4().hex
    async with store.transaction() as session:
        await session.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
    try:
        with pytest.raises(DBAPIError, match="permission denied"):
            async with store.transaction() as session:
                await session.execute(text(f'SET LOCAL ROLE "{role}"'))
                await session.execute(
                    CALL, {"s": work.subject, "at": work.closed_at, "t": None}
                )
        async with store.transaction() as session:
            await session.execute(
                text(
                    f'GRANT EXECUTE ON FUNCTION public.account_lock_financial_erasure(text,timestamptz,uuid) TO "{role}"'
                )
            )
        async with store.transaction() as session:
            await session.execute(text(f'SET LOCAL ROLE "{role}"'))
            await session.execute(
                CALL, {"s": work.subject, "at": work.closed_at, "t": None}
            )
        with pytest.raises(DBAPIError, match="permission denied"):
            async with store.transaction() as session:
                await session.execute(text(f'SET LOCAL ROLE "{role}"'))
                await session.execute(text("SELECT subject FROM account_lifecycles"))
    finally:
        async with store.transaction() as session:
            await session.execute(text(f'DROP OWNED BY "{role}"'))
            await session.execute(text(f'DROP ROLE "{role}"'))


async def test_waiting_erasure_rechecks_the_hold_committed_while_it_waited(jobs):
    store, _ = jobs
    work = await closed_account(store)
    started = asyncio.Future()

    async def attempt_erasure():
        async with store.transaction() as session:
            started.set_result(await session.scalar(text("SELECT pg_backend_pid()")))
            await session.execute(
                CALL, {"s": work.subject, "at": work.closed_at, "t": None}
            )

    task = None
    try:
        async with store.transaction() as session:
            await session.execute(
                text(
                    "UPDATE account_lifecycles SET financial_hold=true,hold_reference='explicit' WHERE subject=:s"
                ),
                {"s": work.subject},
            )
            task = asyncio.create_task(attempt_erasure())
            pid = await started
            async with asyncio.timeout(5):
                while True:
                    async with store.transaction() as observer:
                        waiting = await observer.scalar(
                            text(
                                "SELECT wait_event_type FROM pg_stat_activity WHERE pid=:pid"
                            ),
                            {"pid": pid},
                        )
                    if waiting == "Lock":
                        break
                    await asyncio.sleep(0.01)
            assert not task.done()
        # The function must use the post-lock committed state, even though its
        # calling statement began while the old unheld row was still visible.
        with pytest.raises(DBAPIError, match="Financial erasure authority unavailable"):
            await task
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
async def test_stale_transaction_snapshots_cannot_grant_erasure(jobs, isolation):
    store, _ = jobs
    work = await closed_account(store)
    engine = store.maker.kw["bind"]
    with pytest.raises(DBAPIError, match="requires READ COMMITTED isolation"):
        async with engine.connect() as connection:
            await connection.execution_options(isolation_level=isolation)
            async with connection.begin():
                assert (
                    await connection.scalar(
                        text(
                            "SELECT financial_hold FROM account_lifecycles WHERE subject=:s"
                        ),
                        {"s": work.subject},
                    )
                    is False
                )
                async with store.transaction() as writer:
                    await writer.execute(
                        text(
                            "UPDATE account_lifecycles SET financial_hold=true,hold_reference='explicit' WHERE subject=:s"
                        ),
                        {"s": work.subject},
                    )
                # Prove this is a stale pre-hold snapshot, not an ordinary
                # already-visible hold rejection or a serialization failure.
                assert (
                    await connection.scalar(
                        text(
                            "SELECT financial_hold FROM account_lifecycles WHERE subject=:s"
                        ),
                        {"s": work.subject},
                    )
                    is False
                )
                await connection.execute(
                    CALL, {"s": work.subject, "at": work.closed_at, "t": None}
                )
