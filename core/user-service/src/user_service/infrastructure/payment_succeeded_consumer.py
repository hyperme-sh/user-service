"""payment.succeeded.v1 → paid subscription + tenant.subscription_id."""

from __future__ import annotations

from sqlalchemy import text

from controlplane_api.event_types import PAYMENT_SUCCEEDED_V1
from controlplane_api.config import settings
from controlplane_db.billing_store import get_payment
from api.core.container import container
from api.domain.dtos.tenant_dto import UpdateTenantDto
from api.infrastructure.persistence.db_session import (
    get_session_maker,
    reset_db_session,
    set_db_session,
)
from api.usecases.subscription_plan_service import SubscriptionPlanService
from api.usecases.tenant_service import TenantService
from api.infrastructure.messaging.tenant_event_publisher import build_routing_consumer
from controlplane_events.payloads.payment_events import PaymentSucceededPayload

USER_PAYMENT_GROUP = "user-service-controlplane-events"
DEFAULT_PAID_PLAN_ID = "payment_succeeded"
# USDC payments settle Hypermesh leases and marketplace listings. They share
# payment.succeeded.v1 with subscription invoices but never buy the plan.
# USD stablecoin leases are excluded by the authoritative billing scope below.
NON_PLAN_CURRENCIES = frozenset({"usdc"})


def grants_paid_plan(payload: PaymentSucceededPayload) -> bool:
    """Currency screen only; the handler also requires an owned paid invoice."""
    return (payload.currency or "").strip().lower() not in NON_PLAN_CURRENCIES


def build_payment_succeeded_consumer(database_url: str):
    async def on_payment_succeeded(_envelope, payload: PaymentSucceededPayload) -> None:
        if not grants_paid_plan(payload):
            return
        tid = payload.tenant_id
        maker = get_session_maker()
        async with maker() as session:
            tok = set_db_session(session)
            try:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                    {"tid": str(tid)},
                )
                billing = await session.run_sync(
                    lambda sync: get_payment(sync, tid, payload.billing_record_id)
                )
                if billing is None:
                    # Retry instead of granting from an event whose owner record
                    # is missing or belongs to another tenant.
                    raise ValueError("Payment billing record is unavailable")
                if (
                    billing.scope != "invoice"
                    or billing.payment_type != "stripe_invoice"
                    or billing.status != "succeeded"
                ):
                    return
                sub_svc = container.resolve(SubscriptionPlanService)
                tenant_svc = container.resolve(TenantService)
                uid = str(payload.user_id) if payload.user_id else None
                plan_uuid = await sub_svc.ensure_paid_plan_for_tenant(
                    str(tid),
                    user_id=uid,
                    plan_id=DEFAULT_PAID_PLAN_ID,
                )
                await tenant_svc.update_tenant(
                    str(tid),
                    UpdateTenantDto(subscription_id=str(plan_uuid)),
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                reset_db_session(tok)

    return build_routing_consumer(
        database_url=database_url,
        group_id=USER_PAYMENT_GROUP,
        routes={PAYMENT_SUCCEEDED_V1: (PaymentSucceededPayload, on_payment_succeeded)},
        client_id="user-service-payment-events",
        service_bus_connection_string=settings.azure_service_bus_connection_string,
    )
