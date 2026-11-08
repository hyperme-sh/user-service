"""Compatibility DTOs and purpose credentials; canonical routes live in scope_adapter.

The earlier identity_scope_* HTTP implementation is retired. Its immutable SQL
remains available for provenance inspection, never for canonical provisioning.
"""

import hmac
import os
import uuid
from typing import Literal
from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict


class AuthorityBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str
    tenant_id: uuid.UUID
    organization_id: uuid.UUID
    capability: Literal["member", "manage-members", "purchase"] = "member"


async def service_caller(request: Request):
    supplied = request.headers.get("Authorization", "").encode()
    callers = [
        name
        for name in ("AUTH", "PAYMENT", "PLANE")
        if (token := os.environ.get(name + "_SCOPE_AUTHORITY_TOKEN"))
        and hmac.compare_digest(supplied, ("Bearer " + token).encode())
    ]
    if len(callers) != 1:
        raise HTTPException(401, "Unique service scope credential required")
    return callers[0]


async def legacy_scope_guard(request: Request):
    if (
        os.environ.get("USER_SCOPE_GENERATION")
        or getattr(request.app.state, "scope_generation", None)
    ) and os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        raise HTTPException(403, "Canonical current authority is required")
