"""Actual worker/native database erasure in TEST; production retains its fences."""

import hashlib
import uuid
from unittest.mock import AsyncMock

import pytest
from controlplane_db.models import User
from sqlalchemy import text
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from test_closure_inventory import closed_person
from user_service.closure_worker import ClosureWorker, WorkerUnavailable, check_database
from user_service.models import AccountLifecycle


@pytest.mark.parametrize("test_data", [False, True])
async def test_worker_deletes_recent_unsettled_test_finances_but_preserves_production(
    jobs, monkeypatch, test_data
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    payment = uuid.uuid4()
    key = hashlib.sha256(subject.encode()).hexdigest()
    monkeypatch.setenv("FASTAPI_ENV", "test" if test_data else "production")
    if test_data:
        async with store.transaction() as session:
            await session.execute(
                text(
                    "INSERT INTO account_test_data_policy(singleton,database_oid,database_name,enabled) VALUES(true,(SELECT oid FROM pg_database WHERE datname=current_database()),current_database(),true)"
                )
            )
    try:

        async def seed(store, subject, tenant, user):
            async with store.transaction(tenant) as session:
                await session.execute(
                    text("""INSERT INTO billing_records(id,tenant_id,scope,actor,user_id,payment_type,currency,amount,status,metadata)
                  VALUES(:p,:t,'lease','user',:u,'card','usd',1234,'pending',jsonb_build_object('actor_sub',CAST(:s AS text),'unsettled_test_obligation',true))"""),
                    {"p": payment, "t": tenant, "u": user, "s": subject},
                )
                await session.execute(
                    text(
                        "INSERT INTO payer_mismatch_accounts(account_key,day) VALUES(:k,CURRENT_DATE)"
                    ),
                    {"k": hashlib.sha256(subject.encode()).hexdigest()},
                )

        monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
        work, tenant, user, _ = await closed_person(
            store, records=0, before_request=seed
        )
        # closed_person chooses a fresh canonical account; derive test identities
        # from that actual request rather than a caller-provided owner hint.
        subject = work.subject
        key = hashlib.sha256(subject.encode()).hexdigest()
        async with store.transaction() as session:
            row = await session.get(AccountLifecycle, subject)
            row.financial_hold = True
            row.hold_reference = "still-accepted-hold"
            assert (
                await session.scalar(
                    text(
                        "SELECT financial_retain_until>transaction_timestamp() FROM billing_records WHERE id=:p"
                    ),
                    {"p": payment},
                )
                is True
            )
            assert (
                await session.scalar(
                    text(
                        "SELECT financial_retain_until>transaction_timestamp() FROM payer_mismatch_accounts WHERE account_key=:k"
                    ),
                    {"k": key},
                )
                is True
            )
        identity, owners = AsyncMock(), AsyncMock()
        owners.purge_keys.return_value = {"deleted": 0, "remaining": 0}
        owners.purge_models.return_value = {
            "complete": True,
            "more": False,
            "next_after": None,
            "revisions": 0,
            "validations": 0,
            "lease_targets": 0,
            "completed_at": None,
        }

        async def identity_delete(target, **kwargs):
            assert store.maker.kw["bind"].pool.checkedout() == 0
            async with store.transaction() as session:
                present = await session.scalar(
                    text("SELECT count(*) FROM billing_records WHERE id=:p"),
                    {"p": payment},
                )
                assert present == (0 if test_data else 1)

        identity.delete.side_effect = identity_delete
        claim = store.claim
        monkeypatch.setattr(store, "claim", AsyncMock(return_value=work))
        worker = ClosureWorker(store, identity, owners)
        assert await worker.run_one()
        # Advance only retry scheduling, never a retention/financial clock.
        async with store.transaction() as session:
            await session.execute(
                text(
                    "UPDATE account_lifecycles SET retry_at=transaction_timestamp() WHERE subject=:s"
                ),
                {"s": subject},
            )
        work = await claim(subject)
        monkeypatch.setattr(store, "claim", AsyncMock(return_value=work))
        assert await worker.run_one()
        async with store.transaction() as session:
            row = await session.get(AccountLifecycle, subject)
            remaining = await session.scalar(
                text("SELECT count(*) FROM billing_records WHERE id=:p"), {"p": payment}
            )
            risk = await session.scalar(
                text(
                    "SELECT count(*) FROM payer_mismatch_accounts WHERE account_key=:k"
                ),
                {"k": key},
            )
            assert remaining == risk == (0 if test_data else 1)
            assert (row.state == "deleted") is test_data
            assert (row.financial_deleted_at is not None) is test_data
            if test_data:
                assert row.effects["test_financial_erasure"] == {
                    "complete": True,
                    "roots_complete": True,
                    "remaining": 0,
                    "deleted": 2,
                    "tables": {"billing_records": 1, "payer_mismatch_accounts": 1},
                }
            else:
                assert "test_financial_erasure" not in row.effects
            assert (
                row.financial_hold is True
            )  # TEST ignores the fence; it does not forge its release.
            assert (
                await session.scalar(
                    text("SELECT count(*) FROM account_test_delete_capabilities")
                )
                == 0
            )
    finally:
        if test_data:
            async with store.transaction() as session:
                await session.execute(text("DELETE FROM account_test_data_policy"))


@pytest.mark.parametrize("mode,registered", [("production", True), ("test", False)])
async def test_worker_startup_refuses_environment_database_mode_mismatch(
    jobs, monkeypatch, mode, registered
):
    store, _ = jobs
    monkeypatch.setenv("FASTAPI_ENV", mode)
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    if registered:
        async with store.transaction() as session:
            await session.execute(
                text(
                    "INSERT INTO account_test_data_policy(singleton,database_oid,database_name,enabled) VALUES(true,(SELECT oid FROM pg_database WHERE datname=current_database()),current_database(),true)"
                )
            )
    try:
        with pytest.raises(WorkerUnavailable):
            await check_database(store.maker.kw["bind"])
    finally:
        if registered:
            async with store.transaction() as session:
                await session.execute(text("DELETE FROM account_test_data_policy"))
