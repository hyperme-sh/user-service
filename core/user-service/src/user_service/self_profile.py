"""Read the authenticated subject's existing tenant profile without provisioning."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.infrastructure.persistence.db_session import get_db_session
from auth_service.schemas import AuthMeResponse
from user_service.authority_routes import enabled, selected_scope
from user_service.deps import get_current_user, require_matched_tenant
from user_service.domain.dtos import UserResponse
from user_service.infrastructure.persistence.repos import SqlUserRepository
from user_service.scope_api import legacy_scope_guard
from user_service.scoped_authority import actor_active

router = APIRouter(
    tags=["Self profile"],
    dependencies=[Depends(legacy_scope_guard), Depends(selected_scope)],
)


@router.get(
    "/me/profile",
    response_model=UserResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def own_profile(
    response: Response,
    tenant: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    """Return a durable subject binding, never an email match or issuer UUID guess."""
    if enabled():
        if not await actor_active(session, tenant, me.sub):
            raise HTTPException(403, "Current active identity and tenant required")
    elif not await session.scalar(
        text("SELECT is_active FROM tenants WHERE id=:tenant"), {"tenant": tenant}
    ):
        raise HTTPException(403, "Current active tenant required")
    user = await SqlUserRepository(session).get_by_keycloak_sub(tenant, me.sub)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise HTTPException(404, "Active tenant profile unavailable")
    response.headers["Cache-Control"] = "no-store"
    return UserResponse.model_validate(user)
