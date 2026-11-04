"""Real profile erasure, native financial expiry and worker receipts together."""

import hashlib
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from controlplane_db import migrations
from spanopticon_tests.fixtures.postgres import normalize_sync_sqlalchemy_url
from sqlalchemy import create_engine, text
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from testcontainers.postgres import PostgresContainer
from user_service.closure_erasure import PersonalErasure
from user_service.closure_jobs import ClosureClaimLost
from user_service.closure_worker import ClosureWorker
from user_service.models import AccountLifecycle

OLD_SUBJECT = str(uuid.uuid4())


@pytest.fixture(scope="module")
def jobs_url(require_docker):
    with PostgresContainer("postgres:16-alpine@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416") as pg:
        # Exercise actual adoption/backfill, not a caller-supplied retention clock.
        base_jobs_url = normalize_sync_sqlalchemy_url(pg.get_connection_url())
        migrations.upgrade(base_jobs_url)
        engine = create_engine(base_jobs_url)
        root = Path(migrations.__file__).with_name("migration_chains")
        config = Config()
        config.set_main_option("script_location", str(root))
        config.set_main_option("path_separator", "os")
        config.set_main_option(
            "version_locations", str(root / "payment_service/versions")
        )
        with engine.begin() as cx:
            config.attributes.update(
                connection=cx, version_table="alembic_version_payment_service"
            )
            command.downgrade(config, "payment_service_0078_privacy")
            cx.execute(
                text("""INSERT INTO payer_mismatch_accounts
                (account_key,day,mismatches,reserved_count,reserved_cents,last_mismatch_at)
                VALUES(:key,'2010-02-28',2,0,0,'2010-02-28T12:00:00Z')"""),
                {"key": hashlib.sha256(OLD_SUBJECT.encode()).hexdigest()},
            )
            command.upgrade(config, "head")
        engine.dispose()
        yield base_jobs_url


async def personal_done(
    store, subject, monkeypatch, *, before_request=None, key_receipts=None
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    async with store.transaction() as session:
        await session.execute(
            text("""INSERT INTO users
            (id,keycloak_sub,email,first_name,last_name,gender,is_active)
            VALUES(:id,:s,:email,'Personal','Name','unspecified',true)"""),
            {"id": uuid.uuid4(), "s": subject, "email": subject + "@example.invalid"},
        )
    if before_request is not None:
        await before_request(store, subject)
    if subject == OLD_SUBJECT:
        # A real, current financial dependency keeps this account pending while
        # the independent aged risk row is erased and its zero is invalidated.
        async with store.transaction() as session:
            await session.execute(
                text("""INSERT INTO billing_records
                (id,scope,actor,payment_type,currency,amount,status,metadata)
                VALUES(:id,'lease','user','usdc','usdc',100,'pending',CAST(:metadata AS jsonb))"""),
                {"id": uuid.uuid4(), "metadata": '{"actor_sub": "' + subject + '"}'},
            )
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    work = await store.prepare_platform_profile(work)
    tenants = await store.tenants(work)
    for tenant in tenants:
        await store.prepare_scope(work, tenant)
        await store.scope_effect(
            work, tenant, "api_keys", {"keys": (key_receipts or {}).get(tenant, [])}
        )
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
    await store.mark_closed(work, tenants)
    async with store.transaction() as session:
        await session.execute(
            text(
                "UPDATE account_lifecycles SET retry_at=transaction_timestamp() WHERE subject=:s"
            ),
            {"s": subject},
        )
    work = await store.claim(subject)
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
    assert await PersonalErasure(store, identity, owners).erase(work) is not None
    identity.delete.assert_awaited_once()
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.effects["personal_owners_erased"] is True
        assert row.profile_deleted_at is not None and row.financial_deleted_at is None
        row.retry_at = await session.scalar(text("SELECT transaction_timestamp()"))
    return await store.claim(subject)


async def test_actual_worker_erases_due_risk_after_real_personal_job_without_finishing_other_finances(
    jobs, monkeypatch
):
    store, _ = jobs
    work = await personal_done(store, OLD_SUBJECT, monkeypatch)
    claim = store.claim
    monkeypatch.setattr(store, "claim", AsyncMock(return_value=work))
    worker = ClosureWorker(store, None, None)
    assert await worker.run_one()
    async with store.transaction() as session:
        key = hashlib.sha256(OLD_SUBJECT.encode()).hexdigest()
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM payer_mismatch_accounts WHERE account_key=:key"
                ),
                {"key": key},
            )
            == 0
        )
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM account_financial_source_bindings WHERE owner='payment' AND kind='payer_mismatch_accounts' AND resource=:key"
                ),
                {"key": key},
            )
            == 0
        )
        row = await session.get(AccountLifecycle, OLD_SUBJECT)
        assert row.effects["financial_gc"]["payer_risk"]["remaining"] == 0
        assert row.effects["financial_gc"]["payer_risk"]["epoch"] == row.financial_epoch
        assert row.financial_deleted_at is None and row.state == "deleting"
        assert row.claim_id is None
        row.retry_at = await session.scalar(text("SELECT transaction_timestamp()"))
    # Native finance evidence can still arrive while other obligations remain.
    # A new write must defeat any prior zero; a saved receipt is not a cache.
    async with store.transaction() as session:
        await session.execute(
            text(
                "INSERT INTO payer_mismatch_accounts(account_key,day) VALUES(:key,CURRENT_DATE)"
            ),
            {"key": key},
        )
    retry = await claim(OLD_SUBJECT)
    receipt = await store.erase_payer_risk(retry)
    assert (
        receipt["remaining"] == 1
        and receipt["processed"] == 0
        and receipt["next_due_at"]
    )
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, OLD_SUBJECT)
        assert row.effects["financial_gc"]["payer_risk"]["remaining"] == 1
        assert row.effects["financial_gc"]["payer_risk"]["epoch"] == row.financial_epoch
        assert row.financial_deleted_at is None


async def test_stale_claim_and_missing_personal_completion_cannot_touch_risk(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    work = await store.prepare_platform_profile(work)
    await store.mark_closed(work, [])
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        row.retry_at = await session.scalar(text("SELECT transaction_timestamp()"))
    work = await store.claim(subject)
    with pytest.raises(ClosureClaimLost):
        await store.erase_payer_risk(replace(work, claim_id=uuid.uuid4()))
    with pytest.raises(ValueError, match="Complete personal"):
        await store.erase_payer_risk(work)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert "financial_gc" not in row.effects
        assert row.financial_deleted_at is None
