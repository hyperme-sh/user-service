"""Kafka consumer: payment.succeeded.v1 → paid subscription + tenant.subscription_id."""

from __future__ import annotations

from sqlalchemy import text

from api.common.event_types import PAYMENT_SUCCEEDED_V1
from api.core.container import container
from api.domain.dtos.tenant_dto import UpdateTenantDto
from api.infrastructure.persistence.db_session import (
    get_session_maker,
    reset_db_session,
    set_db_session,
)
from api.usecases.subscription_plan_service import SubscriptionPlanService
from api.usecases.tenant_service import TenantService
from controlplane_events import RoutingControlPlaneConsumer
from controlplane_events.payloads.payment_events import PaymentSucceededPayload

USER_PAYMENT_GROUP = "user-service-controlplane-events"
DEFAULT_PAID_PLAN_ID = "payment_succeeded"


def build_payment_succeeded_consumer(bootstrap_servers: str, topic: str) -> RoutingControlPlaneConsumer:
    async def on_payment_succeeded(_envelope, payload: PaymentSucceededPayload) -> None:
        tid = payload.tenant_id
        maker = get_session_maker()
        async with maker() as session:
            tok = set_db_session(session)
            try:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                    {"tid": str(tid)},
                )
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

    return RoutingControlPlaneConsumer(
        bootstrap_servers,
        [topic],
        USER_PAYMENT_GROUP,
        {PAYMENT_SUCCEEDED_V1: (PaymentSucceededPayload, on_payment_succeeded)},
        client_id="user-service-payment-events",
    )
