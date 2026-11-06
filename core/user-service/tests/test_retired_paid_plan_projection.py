"""Real company projection after native profile erasure does not restore its creator."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from api.infrastructure.persistence.repositories.subscription_plan_repository_impl import (
    SubscriptionPlanRepository,
)
from api.infrastructure.persistence.repositories.tenant_repository_impl import (
    TenantRepository,
)
from api.usecases.subscription_plan_service import SubscriptionPlanService
from api.usecases.tenant_service import TenantService
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.payloads.payment_events import PaymentSucceededPayload
from sqlalchemy import text
from test_closure_inventory import closed_person
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_inventory import FinancialInventory
from user_service.infrastructure import payment_succeeded_consumer as target
from user_service.infrastructure.payment_owner import InvoiceEntitlement


@pytest.mark.parametrize('existing', [False, True])
async def test_paid_projection_after_real_profile_purge_preserves_company_and_financial_facts(jobs, monkeypatch, existing):
    monkeypatch.setenv('ACCOUNT_CLOSURE_RETENTION', 'none')
    store, _ = jobs
    values = {'plan': uuid.uuid4()}

    async def before_request(store, subject, tenant, person):
        values.update(t=tenant, person=person)
        if existing:
            async with store.transaction(tenant) as session:
                await session.execute(text("""INSERT INTO subscription_plans
                    (id,tenant_id,user_id,plan_level,is_trial,actor,plan_id)
                    VALUES(:plan,:t,:person,'{"premium": 1}',true,'tenant','company-trial')"""), values)
                await session.execute(text('UPDATE tenants SET subscription_id=:plan WHERE id=:t'), values)
    work, tenant, person, records = await closed_person(store, before_request=before_request)
    values.update(t=tenant, person=person, billing=records[0])
    async with store.transaction() as session:
        await session.execute(text("UPDATE account_lifecycles SET financial_hold=true,hold_reference='preserve' WHERE subject=:s"), {'s': work.subject})
    assert await FinancialInventory(store).prepare(work)
    work = await store.start_erasure(work)
    await store.purge_profile(work, tenant)
    assert (await store.erase_company_creators(work, tenant))["complete"]
    async with store.transaction(tenant) as session:
        before = await session.scalar(text('SELECT to_jsonb(b) FROM billing_records b WHERE id=:billing'), values)
        assert await session.scalar(text('SELECT keycloak_sub FROM users WHERE id=:person'), values) is None
        assert before['user_id'] == str(person)
    repository = SubscriptionPlanRepository()
    repository.add_audit_log = AsyncMock()
    subscription = SubscriptionPlanService(repository)
    tenant_service = TenantService(TenantRepository())
    async def entitlement(tenant_id, billing_id):
        assert tenant_id == tenant and billing_id == records[0]
        # The erased creator stays on the preserved invoice. Payment authority
        # does not hand that historical reference back as a live customer.
        return InvoiceEntitlement(eligible=True, user_id=None)

    monkeypatch.setattr(target, 'get_session_maker', lambda: store.maker)
    monkeypatch.setattr(target, 'invoice_entitlement', entitlement)
    monkeypatch.setattr(target, 'container', MagicMock(resolve=lambda cls: subscription if cls is SubscriptionPlanService else tenant_service))
    consumer = target.build_payment_succeeded_consumer('postgresql://localhost/unused')
    envelope = ControlPlaneEventEnvelope(event_type='payment.succeeded.v1', service='payment-service', tenant_id=tenant,
        payload=PaymentSucceededPayload(tenant_id=tenant, billing_record_id=records[0], user_id=uuid.uuid4(),
                                      currency='usd', amount_cents=100).to_envelope_payload())
    for _ in range(2):
        await consumer.handle_message(key=None, value=envelope.model_dump_json().encode(), headers={})
    async with store.transaction(tenant) as session:
        row = (await session.execute(text('SELECT id,user_id,plan_level,is_trial FROM subscription_plans WHERE tenant_id=:t'), values)).one()
        assert row.user_id is None and row.plan_level == {'premium': 2} and not row.is_trial
        if existing:
            assert row.id == values['plan']
        assert await session.scalar(text('SELECT subscription_id FROM tenants WHERE id=:t'), values) == row.id
        assert await session.scalar(text('SELECT to_jsonb(b) FROM billing_records b WHERE id=:billing'), values) == before
    assert repository.add_audit_log.await_count == 2
    assert all(call.args[0].user_id is None for call in repository.add_audit_log.await_args_list)
