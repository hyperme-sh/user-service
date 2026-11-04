"""Coordinator receipts commit with native host identity redaction."""

import json
import uuid
from dataclasses import replace

import pytest
from sqlalchemy import text
from test_closure_inventory import closed_person
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_inventory import FinancialInventory
from user_service.closure_jobs import ClosureClaimLost


async def installations(store, subject, tenant, person):
    organization = uuid.uuid4()
    async with store.transaction(tenant) as session:
        await session.execute(
            text(
                "INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:id,:t,'Company resource')"
            ),
            {"id": organization, "t": tenant},
        )
        await session.execute(
            text(
                "INSERT INTO host_organization_bindings(tenant_id,keycloak_sub,organization_id) VALUES(:t,:s,:org)"
            ),
            {"t": tenant, "s": subject, "org": organization},
        )
        for _ in range(3):
            await session.execute(
                text("""INSERT INTO hypermesh_host_registrations
              (id,tenant_id,owner_sub,host_org_id,request,state,created_at,expires_at,decided_at)
              VALUES(:id,:t,:s,:org,CAST(:request AS jsonb),'denied',now(),now(),now())"""),
                {
                    "id": uuid.uuid4(),
                    "t": tenant,
                    "s": subject,
                    "org": organization,
                    "request": json.dumps(
                        {
                            "host_name": "company-resource",
                            "_owner_membership": {
                                "email": subject + "@example.invalid"
                            },
                        }
                    ),
                },
            )


async def test_bounded_host_erasure_keeps_atomic_cumulative_receipts(jobs, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, _, _ = await closed_person(store, before_request=installations)
    assert await FinancialInventory(store).prepare(work)
    work = await store.start_erasure(work)
    receipts = [
        await store.erase_host_associations(work, tenant, limit=1) for _ in range(3)
    ]
    assert [r["complete"] for r in receipts] == [False, False, True]
    assert [r["processed"] for r in receipts] == [2, 3, 4]
    assert [r["remaining"] for r in receipts] == [2, 1, 0]
    assert await store.erase_host_associations(work, tenant, limit=1) == receipts[-1]
    async with store.transaction(tenant) as session:
        stored = await store.scope_view(work, tenant)
        assert stored["effects"]["host_associations_erasure"] == receipts[-1]
        assert "host_associations_progress" not in stored["effects"]
        assert stored["effects"].get("operational_sources_unlinked") is True
        # Cached completion must remain valid when later live work binds sources.
        for kind in ("host_organization_bindings", "hypermesh_jobs", "hypermesh_tunnels", "hypermesh_tickets"):
            await session.execute(text("SELECT account_bind_financial_source(ARRAY[:s],:t,'hypermesh',:kind,:resource)"),
                                  {"s": work.subject, "t": tenant, "kind": kind, "resource": str(uuid.uuid4())})
        assert await session.scalar(text("""SELECT count(*) FROM account_financial_source_bindings
            WHERE subject=:s AND tenant_id=:t AND owner='hypermesh'
              AND kind IN ('host_organization_bindings','hypermesh_jobs','hypermesh_tunnels','hypermesh_tickets')"""),
            {"s": work.subject, "t": tenant}) == 0
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM hypermesh_host_registrations WHERE tenant_id=:t AND owner_sub LIKE 'closed-installation:%'"
                ),
                {"t": tenant},
            )
            == 3
        )
        assert (
            await session.scalar(
                text("SELECT count(*) FROM organizations WHERE tenant_id=:t"),
                {"t": tenant},
            )
            == 1
        )


async def test_stale_worker_cannot_erase_host_identity_metadata(jobs, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    store, _ = jobs
    work, tenant, _, _ = await closed_person(store, before_request=installations)
    assert await FinancialInventory(store).prepare(work)
    work = await store.start_erasure(work)
    with pytest.raises(ClosureClaimLost):
        await store.erase_host_associations(
            replace(work, claim_id=uuid.uuid4()), tenant
        )
    async with store.transaction(tenant) as session:
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM host_organization_bindings WHERE tenant_id=:t AND keycloak_sub=:s"
                ),
                {"t": tenant, "s": work.subject},
            )
            == 1
        )
        assert (
            await session.scalar(
                text(
                    "SELECT count(*) FROM hypermesh_host_registrations WHERE tenant_id=:t AND owner_sub=:s"
                ),
                {"t": tenant, "s": work.subject},
            )
            == 3
        )
