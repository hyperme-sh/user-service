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

    if (
        os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") == "1"
        and request.path_params.get("organization_id") is not None
    ):
        # These existing routes have their own normal authentication dependency.
        # Revalidate a supplied signed session selection before their own checks;
        # an absent credential is still refused by that normal dependency.
        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            from auth_service.deps import get_access_token_claims
            from auth_service.schemas import AuthMeResponse
            from api.infrastructure.persistence.db_session import get_db_session
            from user_service.authority_routes import selected_scope

            claims = await get_access_token_claims(token)
            await selected_scope(
                request, AuthMeResponse.from_claims(claims), claims, get_db_session()
            )
