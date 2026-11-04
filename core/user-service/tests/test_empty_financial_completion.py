"""A deleted account requires native current proof from every financial owner."""

import hashlib
import uuid
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from test_payer_risk_erasure import personal_done
from user_service.closure_jobs import ClosureClaimLost
from user_service.closure_worker import ClosureWorker
from user_service.models import AccountLifecycle


async def test_worker_finishes_source_free_account_and_native_fences_survive_pruning(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    work = await personal_done(store, subject, monkeypatch)
    async with store.transaction() as session:
        before = await session.get(AccountLifecycle, subject)
        user_ids = before.effects["platform_profile"]["user_ids"]
        assert len(user_ids) == 1
    original_claim = store.claim
    monkeypatch.setattr(store, "claim", AsyncMock(return_value=work))
    assert await ClosureWorker(store, None, None).run_one()
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "deleted" and row.financial_deleted_at is not None
        assert row.claim_id is row.claim_until is None
        assert row.last_error is None and "financial_gc" not in row.effects
        assert row.effects["platform_profile"] == {"user_ids": user_ids}
        assert "profile_erasure" not in row.effects
    assert await original_claim(subject) is None
    for command, values in (
        (
            "INSERT INTO payer_mismatch_accounts(account_key,day) VALUES(:key,CURRENT_DATE)",
            {"key": hashlib.sha256(subject.encode()).hexdigest()},
        ),
        (
            "INSERT INTO billing_records(id,user_id,scope,actor,payment_type,currency,amount,status,metadata) VALUES(:id,:person,'lease','user','usdc','usdc',100,'pending','{}')",
            {"id": uuid.uuid4(), "person": uuid.UUID(user_ids[0])},
        ),
    ):
        with pytest.raises(DBAPIError) as error:
            async with store.transaction() as session:
                await session.execute(text(command), values)
        assert getattr(error.value.orig, "sqlstate", None) == "42501"


async def test_current_financial_record_is_pending_even_with_personal_none(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    async with store.transaction() as session:
        await session.execute(
            text(
                "INSERT INTO payer_mismatch_accounts(account_key,day) VALUES(:key,CURRENT_DATE)"
            ),
            {"key": hashlib.sha256(subject.encode()).hexdigest()},
        )
    work = await personal_done(store, subject, monkeypatch)
    result = await store.finish_source_free(work)
    assert result["complete"] is False and result["remaining"] > 0
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "deleting" and row.financial_deleted_at is None
        assert row.claim_id == work.claim_id
        assert "profile_erasure" in row.effects


async def test_missing_owner_producer_is_not_zero_and_stale_epoch_is_not_current(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    work = await personal_done(store, subject, monkeypatch)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        epoch = row.financial_epoch
        with pytest.raises(DBAPIError) as error:
            async with session.begin_nested():
                await session.execute(
                    text("SELECT account_finish_source_free_closure(:s,:at,:epoch)"),
                    {"s": subject, "at": work.closed_at, "epoch": epoch + 1},
                )
        assert getattr(error.value.orig, "sqlstate", None) == "40001"
        with pytest.raises(DBAPIError) as error:
            async with session.begin_nested():
                await session.execute(
                    text(
                        "DROP FUNCTION public.payment_account_financial_state(text,timestamptz)"
                    )
                )
                await session.execute(
                    text("SELECT account_finish_source_free_closure(:s,:at,:epoch)"),
                    {"s": subject, "at": work.closed_at, "epoch": epoch},
                )
        assert getattr(error.value.orig, "sqlstate", None) == "42501"
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.financial_deleted_at is None and row.claim_id == work.claim_id


async def test_preservation_hold_and_stale_claim_cannot_finalize_empty_account(
    jobs, monkeypatch
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    work = await personal_done(store, subject, monkeypatch)
    with pytest.raises(ClosureClaimLost):
        await store.finish_source_free(replace(work, claim_id=uuid.uuid4()))
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        row.financial_hold, row.hold_reference = True, "preserve"
    with pytest.raises(DBAPIError) as error:
        await store.finish_source_free(work)
    assert getattr(error.value.orig, "sqlstate", None) == "42501"
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.financial_deleted_at is None and row.state == "deleting"


@pytest.mark.parametrize("legacy", [True, False])
async def test_actual_company_budget_is_preserved_and_legacy_routing_never_counts_as_zero(
    jobs, monkeypatch, legacy
):
    store, _ = jobs
    subject, budget, tenant = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()

    async def seed_budget(store, subject):
        async with store.transaction() as session:
            await session.execute(
                text("INSERT INTO tenants(id,name,is_active) VALUES(:t,:name,true)"),
                {"t": tenant, "name": str(tenant)},
            )
            person = await session.scalar(
                text("SELECT id FROM users WHERE keycloak_sub=:s"), {"s": subject}
            )
            await session.execute(
                text("""INSERT INTO crypto_agent_budgets
                (id,tenant_id,user_id,owner_pubkey,mint_pubkey,label,ceiling_lamports,allocated_lamports)
                VALUES(:id,:t,:person,'company-wallet','company-mint',:label,1000,:allocated)"""),
                {
                    "id": budget,
                    "t": tenant,
                    "person": person,
                    "label": "fake-usdc" if legacy else "Company reserve",
                    "allocated": 0 if legacy else 700,
                },
            )

    work = await personal_done(store, subject, monkeypatch, before_request=seed_budget)
    async with store.transaction() as session:
        before = await session.scalar(
            text("SELECT to_jsonb(b) FROM crypto_agent_budgets b WHERE id=:id"),
            {"id": budget},
        )
    result = await store.finish_source_free(work)
    assert result["complete"] is (not legacy)
    async with store.transaction() as session:
        assert (
            await session.scalar(
                text("SELECT to_jsonb(b) FROM crypto_agent_budgets b WHERE id=:id"),
                {"id": budget},
            )
            == before
        )
        row = await session.get(AccountLifecycle, subject)
        if legacy:
            assert result["remaining"] > 0 and row.financial_deleted_at is None
            assert before["user_id"] is not None and before["allocated_lamports"] == 0
        else:
            assert (
                row.financial_deleted_at is not None
                and row.claim_id is row.claim_until is None
            )
            assert before["user_id"] is None and before["allocated_lamports"] == 700


async def test_key_retirement_projection_keeps_only_principal_alias_and_blocks_financial_recapture(
    jobs, monkeypatch
):
    store, _ = jobs
    subject, tenant, key = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()

    async def seed_scope(store, subject):
        async with store.transaction() as session:
            await session.execute(
                text("INSERT INTO tenants(id,name,is_active) VALUES(:t,:name,true)"),
                {"t": tenant, "name": str(tenant)},
            )

    # Seed the original broker receipt for a key whose physical row is already
    # gone. This is a native alias-projection test, not live key acceptance.
    work = await personal_done(
        store,
        subject,
        monkeypatch,
        before_request=seed_scope,
        key_receipts={
            tenant: [{"id": str(key), "fingerprint": "a" * 64, "purpose": "inference"}]
        },
    )
    assert (await store.finish_source_free(work))["complete"]
    async with store.transaction(tenant) as session:
        effects = await session.scalar(
            text(
                "SELECT effects FROM account_lifecycle_scopes WHERE subject=:s AND tenant_id=:t"
            ),
            {"s": subject, "t": tenant},
        )
    assert effects["api_keys"] == {"keys": [{"id": str(key), "fingerprint": "a" * 64}]}
    assert effects["hypermesh"] == {"lease_ids": []} and "key_erasure" not in effects
    from types import SimpleNamespace

    from controlplane_identity.account_lifecycle import key_digest, subject_digest
    from user_service.lifecycle_read import denials

    async with store.transaction(tenant) as session:
        snapshot = await denials(
            SimpleNamespace(state=SimpleNamespace(tenant_id=tenant)), session
        )
    assert snapshot["complete"] is True
    assert key_digest(tenant, key) in snapshot["keys"]
    assert "a" * 64 in snapshot["fingerprints"]
    assert subject_digest(tenant, subject) in snapshot["subjects"]
    assert snapshot["leases"] == []
    with pytest.raises(DBAPIError) as error:
        async with store.transaction(tenant) as session:
            await session.execute(
                text("""INSERT INTO billing_records
                (id,tenant_id,scope,actor,payment_type,currency,amount,status,metadata)
                VALUES(:id,:t,'lease','user','usdc','usdc',100,'pending',CAST(:metadata AS jsonb))"""),
                {
                    "id": uuid.uuid4(),
                    "t": tenant,
                    "metadata": '{"actor_sub": "apikey:' + str(key) + '"}',
                },
            )
    assert getattr(error.value.orig, "sqlstate", None) == "42501"


@pytest.mark.parametrize(
    "table,trigger",
    [
        ("billing_records", "billing_financial_epoch"),
        ("payer_mismatch_accounts", "account_financial_epoch"),
        ("hypermesh_leases", "account_financial_not_truncated"),
    ],
)
async def test_registry_marker_cannot_replace_an_installed_native_producer(
    jobs, monkeypatch, table, trigger
):
    store, _ = jobs
    subject = str(uuid.uuid4())
    work = await personal_done(store, subject, monkeypatch)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        epoch = row.financial_epoch
        # Negative-only partial-installation probe. No financial DML or age
        # waiver occurs while the trigger is absent; the savepoint restores it.
        with pytest.raises(DBAPIError) as error:
            async with session.begin_nested():
                await session.execute(text(f"DROP TRIGGER {trigger} ON public.{table}"))
                await session.execute(
                    text("SELECT account_finish_source_free_closure(:s,:at,:epoch)"),
                    {"s": subject, "at": work.closed_at, "epoch": epoch},
                )
        assert getattr(error.value.orig, "sqlstate", None) == "42501"
    async with store.transaction() as session:
        assert (
            await session.get(AccountLifecycle, subject)
        ).financial_deleted_at is None
