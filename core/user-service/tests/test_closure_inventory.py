"""Native source associations survive profile erasure and unavailable producers."""

import uuid
from dataclasses import replace

import pytest
from controlplane_db.models import User
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_erasure import PersonalErasure
from user_service.closure_inventory import FinancialInventory
from user_service.closure_jobs import ClosureClaimLost


async def closed_person(store, *, records=1, before_request=None, hypermesh_receipt=None):
    subject, tenant, person = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()
    identifiers = [uuid.uuid4() for _ in range(records)]
    async with store.transaction(tenant) as session:
        await session.execute(
            text("INSERT INTO tenants(id,name,is_active) VALUES(:t,:s,true)"),
            {"t": tenant, "s": subject},
        )
        session.add(
            User(
                id=person,
                tenant_id=tenant,
                keycloak_sub=subject,
                email=subject + "@example.invalid",
                first_name="Private",
                last_name="Creator",
                gender="unspecified",
                is_active=True,
            )
        )
        await session.flush()
        for identifier in identifiers:
            await session.execute(
                text("""INSERT INTO billing_records
              (id,tenant_id,user_id,scope,actor,payment_type,currency,amount,status)
              VALUES(:id,:t,:u,'invoice','tenant','stripe_invoice','usd',100,'succeeded')"""),
                {"id": identifier, "t": tenant, "u": person},
            )
    if before_request is not None:
        await before_request(store, subject, tenant, person)
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    work = await store.prepare_platform_profile(work)
    tenants = await store.tenants(work)
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
                **(hypermesh_receipt or {} if tid == tenant else {}),
            },
        )
        await store.remember_gateways(work, tid, [])
    await store.mark_closed(work, tenants)
    return await store.claim(subject), tenant, person, identifiers


async def test_inventory_precedes_profile_erasure_without_waiving_financial_hold(
    jobs, monkeypatch
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, person, identifiers = await closed_person(store)
    async with store.transaction(tenant) as session:
        await session.execute(
            text(
                "UPDATE account_lifecycles SET financial_hold=true,hold_reference='preserve' WHERE subject=:s"
            ),
            {"s": work.subject},
        )
        before = (
            await session.execute(
                text(
                    "SELECT actor,user_id,financial_activity_at,financial_retain_until FROM billing_records WHERE id=:id"
                ),
                {"id": identifiers[0]},
            )
        ).one()
    work = await store.start_erasure(work)
    with pytest.raises(DBAPIError, match="inventory is incomplete"):
        await store.purge_profile(work, tenant)
    assert await FinancialInventory(store).prepare(work)
    assert await store.financial_inventory_ready(work)
    await store.purge_profile(work, tenant)
    async with store.transaction(tenant) as session:
        profile = await session.get(User, person)
        assert profile.keycloak_sub is None and profile.first_name == ""
        assert profile.email.startswith("closed+")
        after = (
            await session.execute(
                text(
                    "SELECT actor,user_id,financial_activity_at,financial_retain_until FROM billing_records WHERE id=:id"
                ),
                {"id": identifiers[0]},
            )
        ).one()
        assert after == before
        assert (
            await session.scalar(
                text("SELECT financial_hold FROM account_lifecycles WHERE subject=:s"),
                {"s": work.subject},
            )
            is True
        )
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM account_financial_source_bindings WHERE subject=:s AND kind='payment' AND resource=:id"
                ),
                {"s": work.subject, "id": str(identifiers[0])},
            )
            == 1
        )


async def test_missing_producer_blocks_every_personal_effect(jobs, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, person, _ = await closed_person(store)

    class ForbiddenEffects:
        def __getattr__(self, name):
            async def forbidden(*args, **kwargs):
                pytest.fail("personal effect started without native inventory: " + name)

            return forbidden

    async with store.transaction() as session:
        await session.execute(
            text("DELETE FROM account_financial_fence_versions WHERE owner='hypermesh'")
        )
    try:
        assert (
            await PersonalErasure(store, ForbiddenEffects(), ForbiddenEffects()).erase(
                work
            )
            is None
        )
        async with store.transaction(tenant) as session:
            profile = await session.get(User, person)
            assert profile.keycloak_sub == work.subject
            assert not profile.email.startswith("closed+")
            assert (
                await session.scalar(
                    text(
                        "SELECT count(*) FROM account_financial_source_bindings WHERE subject=:s"
                    ),
                    {"s": work.subject},
                )
                == 0
            )
    finally:
        async with store.transaction() as session:
            await session.execute(
                text("SELECT account_register_financial_fence('hypermesh',1)")
            )


async def test_stale_claim_cannot_prime_any_source(jobs, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, _, _ = await closed_person(store)
    with pytest.raises(ClosureClaimLost):
        await store.prime_financial_inventory(
            replace(work, claim_id=uuid.uuid4()), tenant, "billing"
        )
    async with store.transaction() as session:
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM account_financial_source_bindings WHERE subject=:s"
                ),
                {"s": work.subject},
            )
            == 0
        )


async def test_repeated_bounded_claim_work_reaches_later_scopes(jobs, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, _, identifiers = await closed_person(store, records=3)
    inventory = FinancialInventory(store)
    inventory.BATCH_SIZE = inventory.MAX_NONEMPTY_BATCHES = 1
    for attempt in range(len(identifiers) + 2):
        if await inventory.prepare(work):
            break
    else:
        pytest.fail("earlier empty scopes starved later native inventory")
    assert attempt > 0
    async with store.transaction(tenant) as session:
        assert await session.scalar(
            text(
                "SELECT count(*) FROM account_financial_source_bindings WHERE subject=:s AND owner='billing'"
            ),
            {"s": work.subject},
        ) == len(identifiers)


async def test_boolean_marker_cannot_stand_in_for_native_inventory_version(
    jobs, monkeypatch
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, _, _ = await closed_person(store)
    assert await FinancialInventory(store).prepare(work)
    async with store.transaction(tenant) as session:
        await session.execute(
            text("""UPDATE account_lifecycle_scopes SET effects=
          jsonb_set(effects,'{financial_inventory,hypermesh}','true'::jsonb)
          WHERE tenant_id=:t AND subject=:s"""),
            {"t": tenant, "s": work.subject},
        )
    assert await store.financial_inventory_ready(work) is False
    work = await store.start_erasure(work)
    with pytest.raises(DBAPIError, match="inventory is incomplete"):
        await store.purge_profile(work, tenant)
