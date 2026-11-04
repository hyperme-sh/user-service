"""Reviewer redaction and its durable receipt share the native claim transaction."""

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


async def setup(store, monkeypatch):
    monkeypatch.setenv('ACCOUNT_CLOSURE_RETENTION', 'none')
    values = {key: uuid.uuid4() for key in ('org', 'device')}

    async def before_request(store, subject, tenant, person):
        values.update(s=subject, t=tenant)
        async with store.transaction(tenant) as session:
            await session.execute(text("INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:org,:t,'Company')"), values)
            await session.execute(text("""INSERT INTO hypermesh_devices
                (id,tenant_id,class_id,host_org_id,serial,path_a,path_b_state,loaded_instance_state,
                 enrolled,created_at,sell_state,role)
                VALUES(:device,:t,'native-class',:org,:s,CAST(:path AS jsonb),'green','none',true,now(),'paused','host')"""),
                {**values, 'path': json.dumps({'reviewed_by': subject, 'reviewed_at': '2020-01-02T03:04:05Z', 'intake_result': 'accepted'})})
    work, tenant, _, _ = await closed_person(store, before_request=before_request)
    assert await FinancialInventory(store).prepare(work)
    return await store.start_erasure(work), tenant, values


async def test_reviewer_cleanup_still_runs_after_cached_host_completion(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    assert (await store.erase_host_associations(work, tenant))['complete']
    receipt = await store.erase_device_reviewers(work, tenant)
    assert receipt == {'complete': True, 'processed': 1, 'remaining': 0}
    assert await store.erase_device_reviewers(work, tenant) == receipt
    assert (await store.scope_view(work, tenant))['effects']['device_reviewers_erasure'] == receipt
    async with store.transaction(tenant) as session:
        assert await session.scalar(text("SELECT path_a FROM hypermesh_devices WHERE id=:device"), values) == {
            'reviewed_at': '2020-01-02T03:04:05Z', 'intake_result': 'accepted'}


async def test_stale_claim_cannot_erase_company_reviewer(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    with pytest.raises(ClosureClaimLost):
        await store.erase_device_reviewers(replace(work, claim_id=uuid.uuid4()), tenant)
    async with store.transaction(tenant) as session:
        assert await session.scalar(text("SELECT path_a->>'reviewed_by' FROM hypermesh_devices WHERE id=:device"), values) == work.subject
