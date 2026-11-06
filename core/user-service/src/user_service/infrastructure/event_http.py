"""Authenticated HTTP inbox for owner events.

The events distribution pinned by this service's fixture graph does not export
``controlplane_events.http_consumer``. Handlers stay idempotent: a crash after
the domain commit and before the inbox receipt commits causes redelivery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import create_async_engine

from controlplane_events.contracts import validate_event_envelope
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.store import normalize_async_url


class Delivery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: uuid.UUID
    envelope: ControlPlaneEventEnvelope


class HttpRoutingConsumer:
    def __init__(self, database_url, routes):
        self.routes = routes
        self.engine = create_async_engine(
            normalize_async_url(database_url), pool_pre_ping=True
        )

    async def start(self):
        async with self.engine.connect() as db:
            await db.execute(text("SELECT 1 FROM event_inbox LIMIT 1"))

    async def stop(self):
        await self.engine.dispose()

    async def receive(self, event_id, envelope):
        validate_event_envelope(envelope)
        if envelope.tenant_id is None or envelope.event_type not in self.routes:
            raise ValueError("No tenant-scoped handler for this event")
        event_id = uuid.UUID(str(event_id))
        model, handler = self.routes[envelope.event_type]
        payload = model.model_validate(envelope.payload)
        serialized = envelope.model_dump(mode="json")
        async with self.engine.begin() as db:
            await db.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
                {"tenant": str(envelope.tenant_id)},
            )
            await db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {
                    "key": int.from_bytes(
                        hashlib.sha256(event_id.bytes).digest()[:8], "big", signed=True
                    )
                },
            )
            previous = await db.scalar(
                text("SELECT envelope FROM event_inbox WHERE event_id=:id"),
                {"id": event_id},
            )
            if previous is not None:
                if previous != serialized:
                    raise ValueError("Event identity reused with different facts")
                return False
            await handler(envelope, payload)
            await db.execute(
                text(
                    "INSERT INTO event_inbox(event_id, tenant_id, envelope) "
                    "VALUES (:id, :tenant, :envelope)"
                ).bindparams(bindparam("envelope", type_=JSONB)),
                {
                    "id": event_id,
                    "tenant": envelope.tenant_id,
                    "envelope": serialized,
                },
            )
        return True


def consumer_router():
    router = APIRouter()

    @router.post("/internal/events")
    async def receive_event(request: Request, delivery: Delivery):
        path = os.environ.get("EVENT_PRODUCER_TOKENS_FILE")
        if not path:
            raise HTTPException(503, "Event credentials not configured")
        expected = json.loads(Path(path).read_text()).get(delivery.envelope.service)
        if not expected or not hmac.compare_digest(
            request.headers.get("authorization", "").encode(),
            ("Bearer " + expected).encode(),
        ):
            raise HTTPException(401, "Producer credential required")
        if request.headers.get("idempotency-key") != str(delivery.event_id):
            raise HTTPException(400, "Idempotency key must match event identity")
        consumer = getattr(request.app.state, "event_consumer", None)
        if not isinstance(consumer, HttpRoutingConsumer):
            raise HTTPException(503, "HTTP consumer not configured")
        try:
            created = await consumer.receive(delivery.event_id, delivery.envelope)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {
            "committed": True,
            "duplicate": not created,
            "event_id": str(delivery.event_id),
        }

    return router
