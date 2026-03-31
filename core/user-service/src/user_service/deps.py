from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, status

from auth_service.deps import get_current_tenant as get_current_tenant_from_token

# Re-export auth-service dependencies for routers.
from auth_service.deps import get_current_user  # noqa: F401

MatchedTenantId = uuid.UUID


async def require_matched_tenant(
    request: Request,
    tenant: uuid.UUID = Depends(get_current_tenant_from_token),
) -> MatchedTenantId:
    """RLS GUC (from X-Tenant-ID) must match tenant claim in the access token."""
    raw = request.headers.get("X-Tenant-ID")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-ID header is required",
        )
    try:
        hdr = uuid.UUID(str(raw))
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Tenant-ID",
        ) from e
    if hdr != tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="X-Tenant-ID must match tenant in access token",
        )
    return tenant
