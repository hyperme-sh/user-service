"""Payment actor redaction and cumulative receipts share the native claim."""

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
    values = {key: uuid.uuid4() for key in ('host', 'attempt')}

    async def before_request(store, subject, tenant, person):
        values.update(s=subject, t=tenant)
        async with store.transaction(tenant) as session:
            await session.execute(text("""INSERT INTO connect_recipient_accounts
                (tenant_id,host_org_id,attempt_id,attempted_at,legal_type,country,state,initiated_by_sub)
                VALUES(:t,:host,:attempt,now(),'individual','US','CA',:s)"""), values)
            for _ in range(3):
                grant = uuid.uuid4()
                await session.execute(text("""INSERT INTO connect_access_grants
                    (id,tenant_id,host_org_id,enrollment_attempt_id,platform_id,account_id,owner_sub,member_id,
                     issuer_session,purpose,policy,policy_hash,epoch,parameters,idempotency_key,created_at)
                    VALUES(:grant,:t,:host,:attempt,'acct_platform','acct_company',:s,'private-member',
                      'private-session','maintenance','embedded-api/v1',:hash,1,'{}',:key,now())"""),
                    {**values, 'grant': grant, 'hash': 'a' * 64, 'key': 'connect-access:' + str(grant)})
    work, tenant, _, _ = await closed_person(store, before_request=before_request)
    assert await FinancialInventory(store).prepare(work)
    return await store.start_erasure(work), tenant, values


async def test_bounded_access_redaction_has_atomic_cumulative_receipts(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    receipts = [await store.erase_payment_access(work, tenant, limit=1) for _ in range(3)]
    assert [r['processed'] for r in receipts] == [1, 2, 3]
    assert [r['remaining'] for r in receipts] == [2, 1, 0]
    assert await store.erase_payment_access(work, tenant, limit=1) == receipts[-1]
    effects = (await store.scope_view(work, tenant))['effects']
    assert effects['payment_access_erasure'] == receipts[-1]
    assert 'payment_access_progress' not in effects
    async with store.transaction(tenant) as session:
        assert await session.scalar(text("SELECT count(*) FROM connect_access_grants WHERE tenant_id=:t AND owner_sub LIKE 'closed-access:%'"), values) == 3
        assert await session.scalar(text("SELECT count(*) FROM connect_access_results WHERE tenant_id=:t"), values) == 0


async def test_stale_claim_cannot_remove_payment_actor_evidence(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    with pytest.raises(ClosureClaimLost):
        await store.erase_payment_access(replace(work, claim_id=uuid.uuid4()), tenant)
    async with store.transaction(tenant) as session:
        assert await session.scalar(text("SELECT count(*) FROM connect_access_grants WHERE tenant_id=:t AND owner_sub=:s"), values) == 3
