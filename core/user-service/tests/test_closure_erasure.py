"""Native profile erasure receipts survive retries without touching financial holds."""

import uuid
from datetime import timedelta

import httpx
import pytest
from controlplane_db.models import User
from sqlalchemy import text
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from test_closure_jobs import simulated_database_clock
from user_service.closure_clients import ClosureOwners
from user_service.closure_erasure import PersonalErasure
from user_service.models import AccountLifecycle


@pytest.mark.parametrize("model_evidence", ["complete", "missing", "unbounded"])
async def test_due_erasure_preserves_holds_and_original_native_counts(
    jobs, monkeypatch, model_evidence
):
    store, clock = jobs
    missing_model = model_evidence != "complete"
    await simulated_database_clock(store, clock, monkeypatch)
    subject, tenant, identifier = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()
    async with store.transaction(tenant) as session:
        await session.execute(
            text("INSERT INTO tenants(id,name,is_active) VALUES (:t,:n,true)"),
            {"t": tenant, "n": str(tenant)},
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
                password="secret-profile-password",
            )
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
                "model_ids": [str(uuid.uuid4())] if model_evidence == "missing" else [],
                "lease_ids": [],
                "tickets_revoked": True,
                "new_selling_disabled": True,
            },
        )
        await store.remember_gateways(work, tid, [])
    work = await store.mark_closed(work, tenants)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        row.financial_hold = True
        row.hold_reference = "explicit-preservation"
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://keys.example")
    monkeypatch.setenv("ACCOUNT_CLOSURE_HYPERMESH_URL", "https://mesh.example")
    unavailable, deleted = [True], []

    class Identity:
        async def delete(self, target, *, disable_receipt):
            assert disable_receipt is True
            assert store.maker.kw["bind"].pool.checkedout() == 0
            deleted.append(target)

    async def reply(request):
        assert store.maker.kw["bind"].pool.checkedout() == 0
        if request.url.path.endswith("/purge-models"):
            if model_evidence == "unbounded":
                return httpx.Response(
                    200,
                    json={
                        "complete": False,
                        "more": True,
                        "next_after": str(uuid.uuid4()),
                        "revisions": 0,
                        "validations": 0,
                        "lease_targets": 0,
                        "completed_at": None,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "complete": True,
                    "more": False,
                    "next_after": None,
                    "revisions": 0,
                    "validations": 0,
                    "lease_targets": 0,
                    "completed_at": clock[0].isoformat(),
                },
            )
        assert request.url.path == "/api/v1/api-keys/internal/purge-owner"
        return (
            httpx.Response(503)
            if unavailable[0]
            else httpx.Response(200, json={"deleted": 0, "remaining": 0})
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(reply), trust_env=False
    ) as client:
        eraser = PersonalErasure(store, Identity(), ClosureOwners(client))
        # Closed transition atomically released the claim until erasure is due.
        assert work.claim_id is None
        assert await store.claim(subject) is None
        assert deleted == []
        clock[0] += timedelta(days=89)
        due = await store.claim(subject)
        assert await eraser.erase(due) is None
        assert deleted == [subject]
        async with store.transaction(tenant) as session:
            person = await session.get(User, identifier)
            assert person.keycloak_sub is None and person.password is None
            assert person.first_name == person.last_name == ""
            assert person.email.endswith("@account.invalid") and not person.is_active
            assert person.deleted_at == clock[0]
        # Native profile counts are committed atomically, not recomputed as zero
        # after a different owner loses its response.
        async with store.transaction(tenant) as session:
            from user_service.models import AccountLifecycleScope

            row = await session.get(AccountLifecycleScope, (tenant, subject))
            original = row.effects["profile_erasure"]
            assert original["counts"]["profiles"] == 1
            assert "key_erasure" not in row.effects
        unavailable[0] = False
        clock[0] += timedelta(seconds=31)
        replacement = await store.claim(subject)
        result = await eraser.erase(replacement)
        assert result is None if missing_model else result.state == "deleting"
        assert deleted == [subject]
        async with store.transaction(tenant) as session:
            from user_service.models import AccountLifecycleScope

            row = await session.get(AccountLifecycleScope, (tenant, subject))
            assert row.effects["profile_erasure"] == original
            assert row.effects["api_keys"] == {"keys": []}
            assert row.effects["key_erasure"] == {"remaining": 0}
        async with store.transaction() as session:
            row = await session.get(AccountLifecycle, subject)
            assert row.profile_deleted_at == clock[0] - timedelta(seconds=31)
            assert row.financial_hold and row.hold_reference == "explicit-preservation"
            assert row.financial_deleted_at is None
            assert (row.effects.get("personal_owners_erased") is True) is (
                not missing_model
            )


async def test_test_plane_erases_immediately_despite_a_financial_hold(
    jobs, monkeypatch
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, clock = jobs
    await simulated_database_clock(store, clock, monkeypatch)
    subject, tenant, identifier = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()
    async with store.transaction(tenant) as session:
        await session.execute(
            text("INSERT INTO tenants(id,name,is_active) VALUES (:t,:n,true)"),
            {"t": tenant, "n": str(tenant)},
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
                password="secret-profile-password",
            )
        )
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    work = await store.prepare_platform_profile(work)
    for tid in await store.tenants():
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
        await store.remember_gateways(work, tid, [])
    work = await store.mark_closed(work, await store.tenants())
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        row.financial_hold = True
        row.hold_reference = "explicit-preservation"
        closed_at = row.closed_at
    work = await store.claim(subject)
    assert work is not None  # Test-plane zero retention is scheduled atomically.
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://keys.example")

    monkeypatch.setenv("ACCOUNT_CLOSURE_HYPERMESH_URL", "https://mesh.example")

    class Identity:
        async def delete(self, target, *, disable_receipt):
            assert disable_receipt is True

    async def reply(request):
        if request.url.path.endswith("/purge-models"):
            return httpx.Response(
                200,
                json={
                    "complete": True,
                    "more": False,
                    "next_after": None,
                    "revisions": 0,
                    "validations": 0,
                    "lease_targets": 0,
                    "completed_at": clock[0].isoformat(),
                },
            )
        assert request.url.path == "/api/v1/api-keys/internal/purge-owner"
        return httpx.Response(200, json={"deleted": 0, "remaining": 0})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(reply), trust_env=False
    ) as client:
        result = await PersonalErasure(store, Identity(), ClosureOwners(client)).erase(
            work
        )
    assert result is not None and result.state == "deleting"
    assert clock[0] < closed_at + timedelta(days=89)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.financial_hold and row.hold_reference == "explicit-preservation"
        assert row.financial_deleted_at is None
        assert row.effects["profile_erasure"]["complete"] is True
        assert row.effects["personal_owners_erased"] is True


async def test_fast_worker_clock_cannot_erase_before_database_retention(jobs):
    store, clock = jobs
    subject = str(uuid.uuid4())
    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    work = await store.identity_disabled(work)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        row.state = "closed"
        row.effects = {**row.effects, "scope_discovery": True, "scope_tenants": []}
    clock[0] += timedelta(days=365)
    with pytest.raises(ValueError, match="personal retention boundary"):
        await store.start_erasure(work)
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.state == "closed" and row.profile_deleted_at is None
