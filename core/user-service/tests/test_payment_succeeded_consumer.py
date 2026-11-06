"""Tests for payment.succeeded consumer (handler wiring)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from api.usecases.subscription_plan_service import SubscriptionPlanService
from api.usecases.tenant_service import TenantService
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.payloads.payment_events import PaymentSucceededPayload

from user_service.infrastructure.payment_succeeded_consumer import (
    build_payment_succeeded_consumer,
)


@pytest.mark.asyncio
async def test_payment_succeeded_runs_subscription_and_tenant_update(monkeypatch):
    tid = uuid.uuid4()
    plan_id = uuid.uuid4()
    uid = uuid.uuid4()

    class _Sess:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def execute(self, *a, **k):
            return None

        async def run_sync(self, callback):
            from types import SimpleNamespace

            return SimpleNamespace(
                scope="invoice", payment_type="stripe_invoice", status="succeeded", user_id=uid
            )

        async def commit(self):
            return None

        async def rollback(self):
            return None

    class _Maker:
        def __call__(self):
            return _Sess()

    monkeypatch.setattr(
        "user_service.infrastructure.payment_succeeded_consumer.get_session_maker",
        lambda: _Maker(),
    )

    sub_svc = MagicMock()
    sub_svc.ensure_paid_plan_for_tenant = AsyncMock(return_value=plan_id)
    tenant_svc = MagicMock()
    tenant_svc.update_tenant = AsyncMock()

    def _resolve(cls):
        if cls is SubscriptionPlanService:
            return sub_svc
        if cls is TenantService:
            return tenant_svc
        raise AssertionError(cls)

    monkeypatch.setattr(
        "user_service.infrastructure.payment_succeeded_consumer.container",
        MagicMock(resolve=_resolve),
    )
    monkeypatch.setattr(
        "user_service.infrastructure.payment_succeeded_consumer.invoice_entitlement",
        AsyncMock(return_value=SimpleNamespace(eligible=True, user_id=str(uid))),
    )

    consumer = build_payment_succeeded_consumer("postgresql://localhost/controlplane")
    env = ControlPlaneEventEnvelope(
        event_type="payment.succeeded.v1",
        service="payment-service",
        tenant_id=tid,
        payload=PaymentSucceededPayload(
            tenant_id=tid,
            billing_record_id=uuid.uuid4(),
            user_id=uid,
        ).to_envelope_payload(),
    )
    await consumer.handle_message(
        key=None,
        value=env.model_dump_json().encode("utf-8"),
        headers={},
    )

    sub_svc.ensure_paid_plan_for_tenant.assert_awaited_once()
    tenant_svc.update_tenant.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("currency", ["usdc", "USDC"])
async def test_usdc_lease_payment_does_not_grant_a_subscription(monkeypatch, currency):
    tid = uuid.uuid4()
    sub_svc = MagicMock()
    sub_svc.ensure_paid_plan_for_tenant = AsyncMock()
    tenant_svc = MagicMock()
    tenant_svc.update_tenant = AsyncMock()

    def _resolve(cls):
        if cls is SubscriptionPlanService:
            return sub_svc
        if cls is TenantService:
            return tenant_svc
        raise AssertionError(cls)

    monkeypatch.setattr(
        "user_service.infrastructure.payment_succeeded_consumer.container",
        MagicMock(resolve=_resolve),
    )
    consumer = build_payment_succeeded_consumer("postgresql://localhost/controlplane")
    env = ControlPlaneEventEnvelope(
        event_type="payment.succeeded.v1",
        service="payment-service",
        tenant_id=tid,
        payload=PaymentSucceededPayload(
            tenant_id=tid,
            billing_record_id=uuid.uuid4(),
            currency=currency,
        ).to_envelope_payload(),
    )
    await consumer.handle_message(
        key=None,
        value=env.model_dump_json().encode("utf-8"),
        headers={},
    )
    sub_svc.ensure_paid_plan_for_tenant.assert_not_awaited()
    tenant_svc.update_tenant.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["deposit", "checkout", "invoice", "unpaid_invoice", "foreign", "missing"]
)
async def test_usd_events_require_an_owned_paid_invoice(monkeypatch, kind):
    from user_service.infrastructure import payment_succeeded_consumer as target

    billing_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    entitled = kind == "invoice"
    seen = {}

    async def entitlement(tenant, billing):
        seen["tenant"] = tenant
        seen["billing"] = billing
        return SimpleNamespace(eligible=entitled, user_id=None)

    class _Sess:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, *args, **kwargs):
            return None

        async def commit(self):
            return None

        async def rollback(self):
            return None

    monkeypatch.setattr(target, "get_session_maker", lambda: (lambda: _Sess()))
    monkeypatch.setattr(target, "invoice_entitlement", entitlement)
    sub_svc = MagicMock(
        ensure_paid_plan_for_tenant=AsyncMock(return_value=uuid.uuid4())
    )
    tenant_svc = MagicMock(update_tenant=AsyncMock())
    monkeypatch.setattr(
        target,
        "container",
        MagicMock(
            resolve=lambda cls: sub_svc
            if cls is SubscriptionPlanService
            else tenant_svc
        ),
    )
    consumer = build_payment_succeeded_consumer("postgresql://localhost/controlplane")
    env = ControlPlaneEventEnvelope(
        event_type="payment.succeeded.v1",
        service="payment-service",
        tenant_id=tenant_id,
        payload=PaymentSucceededPayload(
            tenant_id=tenant_id,
            billing_record_id=billing_id,
            user_id=uuid.uuid4(),
            currency="usd",
            amount_cents=2500,
            stripe_payment_intent_id="pi_real",
        ).to_envelope_payload(),
    )
    await consumer.handle_message(
        key=None, value=env.model_dump_json().encode(), headers={}
    )
    assert seen == {"tenant": tenant_id, "billing": billing_id}
    if kind == "invoice":
        sub_svc.ensure_paid_plan_for_tenant.assert_awaited_once_with(
            str(tenant_id), user_id=None, plan_id="payment_succeeded"
        )
        tenant_svc.update_tenant.assert_awaited_once()
    else:
        sub_svc.ensure_paid_plan_for_tenant.assert_not_awaited()
        tenant_svc.update_tenant.assert_not_awaited()
