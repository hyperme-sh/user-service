"""Private worker execution against real claims, RLS and lease replacement."""

import asyncio
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_clients import ClosureOwners
from user_service.closure_worker import (
    ClosureWorker,
    WorkerUnavailable,
    check_database,
    database_url,
    execute,
)
from user_service.models import AccountLifecycle


async def target_claim(store, monkeypatch):
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    claim = store.claim

    async def exact():
        return await claim(subject)

    monkeypatch.setattr(store, "claim", exact)
    return subject


async def test_native_database_preflight_accepts_complete_owner_installation(jobs):
    store, _ = jobs
    await check_database(store.maker.kw["bind"])


async def test_native_preflight_rejects_tenant_reader_before_touching_jobs(
    jobs, jobs_url
):
    store, _ = jobs
    role = "closure_reader_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    async with store.transaction() as session:
        await session.execute(text(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'"))
    url = make_url(jobs_url).set(
        drivername="postgresql+asyncpg", username=role, password=password
    )
    engine = create_async_engine(url)
    try:
        with pytest.raises(WorkerUnavailable):
            await check_database(engine)
    finally:
        await engine.dispose()
        async with store.transaction() as session:
            await session.execute(text(f"DROP ROLE {role}"))


async def test_worker_closes_real_job_without_open_transaction_across_http(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = await target_claim(store, monkeypatch)
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://keys.example")
    disabled = []

    class Identity:
        async def disable(self, target):
            assert store.maker.kw["bind"].pool.checkedout() == 0
            disabled.append(target)

    def respond(request):
        assert store.maker.kw["bind"].pool.checkedout() == 0
        assert request.url.path.endswith("/owner-inventory")
        return httpx.Response(200, json={"keys": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        worker = ClosureWorker(store, Identity(), ClosureOwners(client))
        assert await worker.run(max_jobs=2) == 1
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "closed" and row.closed_at is not None
        assert row.claim_id is None and row.financial_deleted_at is None
        assert row.effects["scope_discovery"] is True
    assert disabled == [subject]


async def test_failed_job_is_released_with_sanitized_error_and_no_false_completion(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = await target_claim(store, monkeypatch)
    worker = ClosureWorker(store, None, None)
    worker.processor.close = AsyncMock(side_effect=RuntimeError("secret provider body"))
    assert await worker.run_one() is True
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "closing" and row.claim_id is None
        assert row.last_error == "owner_conflict" and row.financial_deleted_at is None


async def test_native_claim_replacement_cancels_inflight_owner_without_releasing_successor(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = await target_claim(store, monkeypatch)
    worker = ClosureWorker(store, None, None)
    started, cancelled = asyncio.Event(), asyncio.Event()
    successor = uuid.uuid4()

    async def blocked(work):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async def replace(work):
        await started.wait()
        async with store.transaction() as session:
            await session.execute(
                text("UPDATE account_lifecycles SET claim_id=:id WHERE subject=:s"),
                {"id": successor, "s": subject},
            )
        await store.heartbeat(work)

    worker.processor.close = blocked
    monkeypatch.setattr(worker, "_renew", replace)
    assert await worker.run_one() is True
    assert cancelled.is_set()
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.claim_id == successor and row.last_error is None


async def test_shutdown_cancels_owner_then_releases_only_owned_native_claim(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = await target_claim(store, monkeypatch)
    worker = ClosureWorker(store, None, None)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def blocked(work):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    worker.processor.close = blocked
    task = asyncio.create_task(worker.run_one())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.claim_id is None and row.last_error == "owner_unavailable"
        assert row.financial_deleted_at is None


@pytest.mark.parametrize("value", [None, True, 0, 101, 1.0])
async def test_batch_bounds_reject_before_claiming(value):
    store = AsyncMock()
    with pytest.raises(ValueError):
        await ClosureWorker(store, None, None).run(max_jobs=value)
    store.claim.assert_not_awaited()


async def test_disabled_worker_never_connects_or_reads_writer_configuration(
    monkeypatch,
):
    monkeypatch.delenv("ACCOUNT_CLOSURE_WORKER_ENABLED", raising=False)
    with pytest.raises(WorkerUnavailable):
        await execute(max_jobs=1)


@pytest.mark.parametrize(
    "value", [None, "", "not a DSN", "postgresql+asyncpg://reader@localhost/test"]
)
def test_private_dsn_has_no_public_fallback(monkeypatch, value):
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+asyncpg://public:secret@localhost/test"
    )
    if value is None:
        monkeypatch.delenv("ACCOUNT_CLOSURE_WORKER_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("ACCOUNT_CLOSURE_WORKER_DATABASE_URL", value)
    with pytest.raises(WorkerUnavailable):
        database_url()


async def test_heartbeat_renews_native_claim_while_owner_is_waiting(jobs, monkeypatch):
    import user_service.closure_worker as module

    store, _ = jobs
    subject = await target_claim(store, monkeypatch)
    worker = ClosureWorker(store, None, None)
    renewed, finish = asyncio.Event(), asyncio.Event()
    heartbeat = store.heartbeat

    async def waiting(work):
        async with store.transaction() as session:
            await session.execute(
                text(
                    "UPDATE account_lifecycles SET claim_until=transaction_timestamp()+interval '1 second' WHERE subject=:s"
                ),
                {"s": subject},
            )
        await finish.wait()
        await store.release(work, error="deadline_pending")

    async def renew(work):
        await heartbeat(work)
        renewed.set()

    worker.processor.close = waiting
    monkeypatch.setattr(module, "HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(store, "heartbeat", renew)
    task = asyncio.create_task(worker.run_one())
    try:
        await asyncio.wait_for(renewed.wait(), timeout=5)
        async with store.transaction() as session:
            remaining = await session.scalar(
                text(
                    "SELECT claim_until > transaction_timestamp()+interval '50 seconds' FROM account_lifecycles WHERE subject=:s"
                ),
                {"s": subject},
            )
            assert remaining is True
    finally:
        finish.set()
        await task


async def test_personal_dispatch_failure_cannot_claim_financial_completion(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = await target_claim(store, monkeypatch)
    async with store.transaction() as session:
        # A partially closed row is deliberately insufficient personal authority.
        # The real PersonalErasure guard must fail before touching any provider.
        row = await session.get(AccountLifecycle, subject)
        row.state = "closed"
    worker = ClosureWorker(store, None, None)
    assert await worker.run_one() is True
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "closed" and row.claim_id is None
        assert row.last_error == "owner_conflict"
        assert row.profile_deleted_at is None and row.financial_deleted_at is None
