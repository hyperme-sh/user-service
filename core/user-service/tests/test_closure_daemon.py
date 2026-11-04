"""The private poller advances real due jobs without changing retention clocks."""

import asyncio
import uuid
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import text
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service import closure_daemon as daemon
from user_service.closure_worker import ClosureWorker, WorkerUnavailable
from user_service.models import AccountLifecycle


async def test_three_native_ticks_close_erase_and_finalize_a_source_free_account(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    await store.request(subject, subject, "self_service")
    identity, owners = AsyncMock(), AsyncMock()
    owners.key_tenants.return_value = []
    worker = ClosureWorker(store, identity, owners)
    ticks, pauses = [], []

    async def execute(*, max_jobs):
        assert max_jobs == 1
        async with store.transaction() as session:
            ticks.append((await session.get(AccountLifecycle, subject)).state)
        return await worker.run(max_jobs=max_jobs)

    async def pause(seconds):
        pauses.append(seconds)
        if len(pauses) == 3:
            raise asyncio.CancelledError
        # Polling never supplies a financial age. This account has no sources;
        # personal test waiting alone is waived through the approved policy.
        async with store.transaction() as session:
            await session.execute(
                text(
                    "UPDATE account_lifecycles SET retry_at=transaction_timestamp() WHERE subject=:s"
                ),
                {"s": subject},
            )

    monkeypatch.setattr(daemon, "execute", execute)
    monkeypatch.setattr(daemon, "_wait", pause)
    with pytest.raises(asyncio.CancelledError):
        await daemon.serve(max_jobs=1, poll_seconds=30)
    assert ticks == ["closing", "closed", "deleting"] and pauses == [30, 30, 30]
    identity.disable.assert_awaited_once_with(subject)
    identity.delete.assert_awaited_once_with(subject, disable_receipt=True)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "deleted" and row.financial_deleted_at is not None
        assert row.claim_id is row.claim_until is None
    assert await store.claim(subject) is None


@pytest.mark.parametrize(
    "jobs,interval", [(0, 30), (101, 30), (True, 30), (1, 0), (1, 301), (1, True)]
)
async def test_invalid_schedule_cannot_open_runtime(jobs, interval, monkeypatch):
    execute = AsyncMock()
    monkeypatch.setattr(daemon, "execute", execute)
    with pytest.raises(ValueError):
        await daemon.serve(max_jobs=jobs, poll_seconds=interval)
    execute.assert_not_awaited()


async def test_startup_failure_does_not_spin_or_hide_misconfiguration(monkeypatch):
    execute, pause = AsyncMock(side_effect=WorkerUnavailable()), AsyncMock()
    monkeypatch.setattr(daemon, "execute", execute)
    monkeypatch.setattr(daemon, "_wait", pause)
    with pytest.raises(WorkerUnavailable):
        await daemon.serve(max_jobs=10, poll_seconds=30)
    execute.assert_awaited_once()
    pause.assert_not_awaited()


async def test_cancellation_reaches_native_worker_and_releases_owned_claim(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    claim = store.claim
    monkeypatch.setattr(store, "claim", lambda: claim(subject))
    worker = ClosureWorker(store, None, None)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def blocked(work):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    worker.processor.close = blocked

    async def execute(*, max_jobs):
        return await worker.run(max_jobs=max_jobs)

    monkeypatch.setattr(daemon, "execute", execute)
    task = asyncio.create_task(daemon.serve(max_jobs=1, poll_seconds=30))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.claim_id is None and row.last_error == "owner_unavailable"
        assert row.financial_deleted_at is None
