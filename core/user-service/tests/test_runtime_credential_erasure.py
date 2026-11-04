"""Native runtime cleanup and coordinator progress share the claim transaction."""

import uuid
from dataclasses import replace

import pytest
from sqlalchemy import text
from test_closure_inventory import closed_person
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_inventory import FinancialInventory
from user_service.closure_jobs import ClosureClaimLost


async def setup(store, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    values = {key: uuid.uuid4() for key in ("org", "device", "lease", "job")}
    owner = {"lease_ids": [str(values["lease"])]}

    async def before_request(store, subject, tenant, person):
        values.update(t=tenant, s=subject, person=person)
        async with store.transaction(tenant) as session:
            await session.execute(text("INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:org,:t,'Company host')"), values)
            await session.execute(text("""INSERT INTO hypermesh_devices
                (id,tenant_id,class_id,host_org_id,serial,path_a,path_b_state,loaded_instance_state,
                 enrolled,created_at,sell_state,role)
                VALUES(:device,:t,'native-class',:org,:s,'{}','green','none',true,now(),'paused','host')"""), values)
            await session.execute(text("""INSERT INTO hypermesh_leases
                (id,tenant_id,kind,status,renter_user_id,class_id,host_org_id,device_id,
                 reserved_hours,created_at,token_count,loaded_hours,purpose)
                VALUES(:lease,:t,'p1_hardware','active',:person,'native-class',:org,:device,1,now(),0,0,'renter')"""), values)
            await session.execute(text("""INSERT INTO hypermesh_jobs
                (id,tenant_id,device_id,lease_id,kind,status,created_at,ticket)
                VALUES(:job,:t,:device,:lease,'lease_start','pending',now(),'retained-runtime-token')"""), values)
    work, tenant, _, _ = await closed_person(store, before_request=before_request, hypermesh_receipt=owner)
    assert await FinancialInventory(store).prepare(work)
    return await store.start_erasure(work), tenant, values


async def finish(store, tenant, values):
    async with store.transaction(tenant) as session:
        await session.execute(text("UPDATE hypermesh_leases SET status='ended',ended_at=now() WHERE id=:lease"), values)
        await session.execute(text("UPDATE hypermesh_jobs SET status='passed',completed_at=now() WHERE id=:job"), values)


async def test_active_credentials_keep_owner_pending_until_native_completion(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    assert await store.erase_runtime_credentials(work, tenant) == {"complete": False, "processed": 0, "remaining": 2}
    scope = await store.scope_view(work, tenant)
    assert "runtime_credentials_erasure" not in scope["effects"]
    await finish(store, tenant, values)
    receipt = await store.erase_runtime_credentials(work, tenant)
    assert receipt == {"complete": True, "processed": 1, "remaining": 0}
    assert await store.erase_runtime_credentials(work, tenant) == receipt
    scope = await store.scope_view(work, tenant)
    assert scope["effects"]["runtime_credentials_erasure"] == receipt
    assert scope["effects"]["operational_sources_unlinked"] is True
    assert "runtime_credentials_progress" not in scope["effects"]
    async with store.transaction(tenant) as session:
        assert await session.scalar(text("SELECT ticket FROM hypermesh_jobs WHERE id=:job"), values) is None
        assert await session.scalar(text("SELECT status FROM hypermesh_leases WHERE id=:lease"), values) == "ended"


async def test_stale_claim_cannot_clear_completed_job_credential(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    await finish(store, tenant, values)
    with pytest.raises(ClosureClaimLost):
        await store.erase_runtime_credentials(replace(work, claim_id=uuid.uuid4()), tenant)
    async with store.transaction(tenant) as session:
        assert await session.scalar(text("SELECT ticket FROM hypermesh_jobs WHERE id=:job"), values) == "retained-runtime-token"
