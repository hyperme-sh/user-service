"""Tests for payment.succeeded consumer (handler wiring)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from api.usecases.subscription_plan_service import SubscriptionPlanService
from api.usecases.tenant_service import TenantService
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.payloads.payment_events import PaymentSucceededPayload

from user_service.infrastructure.payment_succeeded_consumer import build_payment_succeeded_consumer


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
