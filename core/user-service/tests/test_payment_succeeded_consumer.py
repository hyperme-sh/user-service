"""Tests for payment.succeeded consumer (handler wiring)."""

from __future__ import annotations

import uuid
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
                scope="invoice", payment_type="stripe_invoice", status="succeeded"
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
async def test_usd_events_require_an_owned_paid_invoice(
    monkeypatch, migrated_sync_url, seed, kind
):
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from controlplane_db.session import normalize_database_url
    from controlplane_db.billing_store import BillingPayment, add_payment
    from user_service.infrastructure import payment_succeeded_consumer as target

    billing_id = uuid.uuid4()
    sync = create_engine(migrated_sync_url)
    try:
        if kind != "missing":
            with Session(sync) as db:
                tenant = seed.tb if kind == "foreign" else seed.ta
                db.execute(
                    text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                    {"tid": str(tenant)},
                )
                invoice = kind in {"invoice", "unpaid_invoice", "foreign"}
                row = BillingPayment(
                    id=billing_id,
                    tenant_id=tenant,
                    scope="invoice" if invoice else "lease",
                    actor="user",
                    payment_type="stripe_invoice" if invoice else "usdc",
                    currency="usd",
                    amount=2500,
                    status="pending" if kind == "unpaid_invoice" else "succeeded",
                    stripe_session_id="cs_checkout" if kind == "checkout" else None,
                    extra_metadata={
                        "payment_rail": "stripe_stablecoin",
                        **(
                            {"stripe_deposit": {"intent_id": "pi_deposit"}}
                            if kind == "deposit"
                            else {}
                        ),
                    },
                )
                add_payment(db, row)
                db.commit()
    finally:
        sync.dispose()
    async_url = normalize_database_url(
        migrated_sync_url.replace("postgresql+psycopg://", "postgresql://", 1)
    )
    engine = create_async_engine(async_url)
    monkeypatch.setattr(
        target,
        "get_session_maker",
        lambda: async_sessionmaker(engine, expire_on_commit=False),
    )
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
    consumer = build_payment_succeeded_consumer(async_url)
    env = ControlPlaneEventEnvelope(
        event_type="payment.succeeded.v1",
        service="payment-service",
        tenant_id=seed.ta,
        payload=PaymentSucceededPayload(
            tenant_id=seed.ta,
            billing_record_id=billing_id,
            currency="usd",
            amount_cents=2500,
            stripe_payment_intent_id="pi_real",
        ).to_envelope_payload(),
    )
    try:
        if kind in {"missing", "foreign"}:
            with pytest.raises(ValueError, match="billing record is unavailable"):
                await consumer.handle_message(
                    key=None, value=env.model_dump_json().encode(), headers={}
                )
        else:
            await consumer.handle_message(
                key=None, value=env.model_dump_json().encode(), headers={}
            )
        if kind == "invoice":
            sub_svc.ensure_paid_plan_for_tenant.assert_awaited_once()
            tenant_svc.update_tenant.assert_awaited_once()
        else:
            sub_svc.ensure_paid_plan_for_tenant.assert_not_awaited()
            tenant_svc.update_tenant.assert_not_awaited()
    finally:
        await engine.dispose()
