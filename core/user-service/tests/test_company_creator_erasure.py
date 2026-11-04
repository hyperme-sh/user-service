"""Native creator cleanup, minimum financial routing and claim receipts stay atomic."""

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
    values = {'legacy': uuid.uuid4(), 'plan': uuid.uuid4()}

    async def before_request(store, subject, tenant, person):
        values.update(s=subject, t=tenant, person=person)
        async with store.transaction(tenant) as session:
            for identifier, label in [(uuid.uuid4(), 'Company') for _ in range(3)] + [(values['legacy'], 'fake-usdc')]:
                await session.execute(text("""INSERT INTO crypto_agent_budgets
                    (id,tenant_id,user_id,owner_pubkey,mint_pubkey,label,ceiling_lamports,allocated_lamports)
                    VALUES(:id,:t,:person,'company-wallet','company-mint',:label,1000,700)"""),
                    {**values, 'id': identifier, 'label': label})
            await session.execute(text("""INSERT INTO subscription_plans
                (id,tenant_id,user_id,plan_level,is_trial,actor,plan_id)
                VALUES(:plan,:t,:person,'{"premium": 2}',false,'tenant','company-plan')"""), values)
            await session.execute(text('UPDATE tenants SET subscription_id=:plan WHERE id=:t'), values)
    work, tenant, _, _ = await closed_person(store, before_request=before_request)
    assert await FinancialInventory(store).prepare(work)
    work = await store.start_erasure(work)
    await store.purge_profile(work, tenant)
    return work, tenant, values


async def test_bounded_creator_receipts_preserve_native_retention_marker_and_company_funds(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    receipts = [await store.erase_company_creators(work, tenant, limit=1) for _ in range(3)]
    assert [r['processed'] for r in receipts] == [2, 3, 4]
    assert [r['remaining'] for r in receipts] == [2, 1, 0]
    assert await store.erase_company_creators(work, tenant, limit=1) == receipts[-1]
    effects = (await store.scope_view(work, tenant))['effects']
    assert effects['company_creators_erasure'] == receipts[-1]
    assert effects['retained_budget_references'] == 1
    assert effects['company_creator_refs_unlinked']
    assert 'company_creators_progress' not in effects
    async with store.transaction(tenant) as session:
        assert await session.scalar(text('SELECT user_id FROM crypto_agent_budgets WHERE id=:legacy'), values) == values['person']
        assert await session.scalar(text('SELECT sum(allocated_lamports) FROM crypto_agent_budgets WHERE tenant_id=:t'), values) == 2800
        assert await session.scalar(text('SELECT subscription_id FROM tenants WHERE id=:t'), values) == values['plan']
        await session.execute(text("UPDATE crypto_agent_budgets SET label='Company reserve' WHERE id=:legacy"), values)
        assert await session.scalar(text('SELECT user_id FROM crypto_agent_budgets WHERE id=:legacy'), values) is None
    assert await store.erase_company_creators(work, tenant, limit=1) == receipts[-1]


async def test_stale_creator_claim_cannot_unlink_company_data(jobs, monkeypatch):
    store, _ = jobs
    work, tenant, values = await setup(store, monkeypatch)
    with pytest.raises(ClosureClaimLost):
        await store.erase_company_creators(replace(work, claim_id=uuid.uuid4()), tenant)
    async with store.transaction(tenant) as session:
        assert await session.scalar(text('SELECT count(*) FROM crypto_agent_budgets WHERE tenant_id=:t AND user_id=:person'), values) == 4
        assert await session.scalar(text('SELECT user_id FROM subscription_plans WHERE id=:plan'), values) == values['person']
