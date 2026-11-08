"""Normal authenticated owner checks and organization-scoped member administration."""

import os
from typing import Literal
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from api.infrastructure.persistence.db_session import get_db_session
from auth_service.schemas import AuthMeResponse
from user_service.deps import get_current_user, require_matched_tenant
from user_service.scoped_authority import (
    allowed,
    require,
    scope,
    identity_active,
    tenant_admin,
)

router = APIRouter()


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    request_id: uuid.UUID
    action: Literal[
        "network.admin",
        "tenant.admin",
        "approval.resolve",
        "organization.read",
        "organization.admin",
        "lease.purchase",
    ]
    network: str | None = Field(default=None, min_length=1, max_length=255)
    tenant_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def target(self):
        if self.action == "network.admin":
            if (
                not self.network
                or self.tenant_id is not None
                or self.organization_id is not None
            ):
                raise ValueError("Network action requires only a network target")
        elif self.network is not None or self.tenant_id is None:
            raise ValueError("Tenant-bound action requires a tenant")
        elif (
            self.action in ("tenant.admin", "approval.resolve")
            and self.organization_id is not None
        ):
            raise ValueError("Tenant action has no organization target")
        elif self.action.startswith("organization.") or self.action == "lease.purchase":
            if self.organization_id is None:
                raise ValueError("Organization target required")
        return self


def enabled():
    return os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") == "1"


@router.post("/authority/check")
async def check_authority(
    body: Check,
    request: Request,
    response: Response,
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    if not enabled():
        raise HTTPException(503, "Scoped authority is not activated")
    response.headers["Cache-Control"] = "no-store"
    if body.tenant_id is not None:
        if me.tenant_id != body.tenant_id or request.headers.get("X-Tenant-ID") != str(
            body.tenant_id
        ):
            raise HTTPException(403, "Authority target must match the verified tenant")
    elif request.headers.get("X-Tenant-ID") is not None and request.headers[
        "X-Tenant-ID"
    ] != str(me.tenant_id):
        raise HTTPException(403, "Tenant cross-check differs")
    result = await allowed(
        session,
        subject=me.sub,
        action=body.action,
        tenant=body.tenant_id,
        organization=body.organization_id,
        network=body.network,
    )
    return {**body.model_dump(mode="json"), "subject": me.sub, "allowed": result}


class MemberWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: uuid.UUID
    role: Literal["admin", "member"] = "member"
    can_purchase_leases: StrictBool = False


async def org_admin(session, tenant, organization, me):
    if not enabled():
        raise HTTPException(503, "Scoped authority is not activated")
    await require(
        session,
        subject=me.sub,
        action="organization.admin",
        tenant=tenant,
        organization=organization,
    )


@router.put("/organizations/{organization_id}/members/{user_id}")
async def put_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    body: MemberWrite,
    me: AuthMeResponse = Depends(get_current_user),
    tenant: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
):
    if body.user_id != user_id:
        raise HTTPException(422, "Member path differs from body")
    await org_admin(session, tenant, organization_id, me)
    async with scope(session, tenant):
        # Membership administration cannot revive a disabled/deleted tenant identity.
        exists = await session.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=:id AND tenant_id=:tenant AND is_active AND deleted_at IS NULL)"
            ),
            {"id": user_id, "tenant": tenant},
        )
        if not exists:
            raise HTTPException(404, "Active tenant identity unavailable")
        subject = await session.scalar(
            text("SELECT keycloak_sub FROM users WHERE id=:id AND tenant_id=:tenant"),
            {"id": user_id, "tenant": tenant},
        )
        if not await identity_active(session, subject):
            raise HTTPException(404, "Active identity unavailable")
        memberships = set(
            (
                await session.execute(
                    text(
                        "SELECT organization_id FROM organization_memberships WHERE tenant_id=:tenant AND user_id=:user AND enabled"
                    ),
                    {"tenant": tenant, "user": user_id},
                )
            ).scalars()
        )
        if (
            memberships
            and organization_id not in memberships
            and not await tenant_admin(session, tenant, me.sub)
        ):
            raise HTTPException(
                403, "Another org identity requires a separate authorized invitation"
            )
        await session.execute(
            text(
                """INSERT INTO organization_memberships(tenant_id,organization_id,user_id,role,can_purchase_leases,enabled)
            VALUES(:tenant,:org,:user,:role,:pays,true) ON CONFLICT(tenant_id,organization_id,user_id)
            DO UPDATE SET role=excluded.role,can_purchase_leases=excluded.can_purchase_leases,enabled=true"""
            ),
            {
                "tenant": tenant,
                "org": organization_id,
                "user": user_id,
                "role": body.role,
                "pays": body.can_purchase_leases,
            },
        )
    return {"organization_id": organization_id, **body.model_dump(), "enabled": True}


@router.delete("/organizations/{organization_id}/members/{user_id}", status_code=204)
async def remove_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    me: AuthMeResponse = Depends(get_current_user),
    tenant: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
):
    await org_admin(session, tenant, organization_id, me)
    async with scope(session, tenant):
        # Revoke only this org membership. Other orgs and global identity survive.
        await session.execute(
            text(
                "UPDATE organization_memberships SET enabled=false WHERE tenant_id=:tenant AND organization_id=:org AND user_id=:user"
            ),
            {"tenant": tenant, "org": organization_id, "user": user_id},
        )


@router.get("/organizations/{organization_id}/members")
async def members(
    organization_id: uuid.UUID,
    me: AuthMeResponse = Depends(get_current_user),
    tenant: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
):
    await org_admin(session, tenant, organization_id, me)
    async with scope(session, tenant):
        rows = (
            (
                await session.execute(
                    text(
                        "SELECT user_id,role,can_purchase_leases,enabled FROM organization_memberships WHERE tenant_id=:tenant AND organization_id=:org ORDER BY user_id"
                    ),
                    {"tenant": tenant, "org": organization_id},
                )
            )
            .mappings()
            .all()
        )
    return {"organization_id": organization_id, "items": [dict(row) for row in rows]}


@router.post("/organizations/{organization_id}/members", status_code=201)
async def create_member(
    organization_id: uuid.UUID,
    body: MemberWrite,
    me: AuthMeResponse = Depends(get_current_user),
    tenant: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
):
    return await put_member(organization_id, body.user_id, body, me, tenant, session)
