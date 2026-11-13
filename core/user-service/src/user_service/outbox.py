"""Directory facts written in the business session; delivery belongs to the relay."""
from __future__ import annotations

import uuid
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from controlplane_events.contracts import validate_event_envelope
from controlplane_events.delivery import MAX_DELIVERY_BYTES, delivery_body
from controlplane_events.envelope import ControlPlaneEventEnvelope
from controlplane_events.publisher import refuse_forbidden_payload

_INSERT = text("""
INSERT INTO service_outbox (id, tenant_id, envelope)
VALUES (:id, :tenant, :envelope)
ON CONFLICT (id) DO NOTHING RETURNING id
""").bindparams(bindparam("envelope", type_=JSONB))


async def publish_directory_event(session, *, tenant_id, event_type, operation_id, payload):
    """Retry the same object/operation once; never open or commit another session."""
    tenant_id = uuid.UUID(str(tenant_id))
    operation_id = uuid.UUID(str(operation_id))
    event_id = uuid.uuid5(uuid.NAMESPACE_URL, f"user-service:{tenant_id}:{event_type}:{operation_id}")
    refuse_forbidden_payload(payload)
    envelope = ControlPlaneEventEnvelope(
        service="user-service", tenant_id=tenant_id, event_type=event_type, payload=payload,
    )
    validate_event_envelope(envelope)
    if len(delivery_body(event_id, envelope)) > MAX_DELIVERY_BYTES:
        raise ValueError("directory event exceeds delivery limit")
    encoded = envelope.model_dump(mode="json")
    result = await session.execute(_INSERT, {"id": event_id, "tenant": tenant_id, "envelope": encoded})
    if result.scalar_one_or_none() is None:
        prior = (await session.execute(text(
            "SELECT envelope FROM service_outbox WHERE id=:id AND tenant_id=:tenant"
        ), {"id": event_id, "tenant": tenant_id})).scalar_one()
        fields = ("service", "tenant_id", "event_type", "schema_version", "payload")
        if any(prior.get(name) != encoded.get(name) for name in fields):
            raise ValueError("directory event operation conflicts with its existing payload")
    elif "directory_event_sink" in session.info:
        session.info.setdefault("directory_events", []).append(encoded)
    return event_id
