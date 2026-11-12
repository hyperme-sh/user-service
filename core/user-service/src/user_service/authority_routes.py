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
from auth_service.deps import get_access_token_claims
from user_service.deps import get_current_user, require_matched_tenant
from user_service.scoped_authority import (
    allowed,
    require,
    scope,
    identity_active,
    tenant_admin,
)


async def selected_scope(
    request: Request,
    me: AuthMeResponse = Depends(get_current_user),
    claims: dict = Depends(get_access_token_claims),
    session: AsyncSession = Depends(get_db_session),
):
    """A signed org selection narrows current authority; it never grants it."""
    if claims.get("scope_version") != 1:
        return
    from user_service.scoped_authority import tenant_network

    try:
        tenant = uuid.UUID(str(claims["tenant_id"]))
    except (KeyError, ValueError, TypeError):
        raise HTTPException(403, "Signed scope tenant is invalid")
    if (
        claims.get("sub") != me.sub
        or claims.get("spanopticon_auth") != "tenant_session"
    ):
        raise HTTPException(403, "Verified scope identity required")
    seal = (
        await session.execute(
            text("SELECT generation,manifest_sha256 FROM authority_fixture_generation")
        )
    ).one_or_none()
    if claims.get('scope_generation') == 'startup-v1':
        from user_service.startup_identity import startup_scope_identity
        startup = await startup_scope_identity(session,tenant,me.sub)
        seal = startup[1:] if startup else None
    network = await tenant_network(session, tenant)
    if (
        seal is None
        or (claims.get("scope_generation"), claims.get("scope_manifest_sha256"))
        != tuple(seal)
        or claims.get("network_id") != network
    ):
        raise HTTPException(403, "Signed scope generation differs")
    if claims.get("scope_kind") == "network":
        return
    selected = claims.get("organization_id")
    try:
        selected = uuid.UUID(str(selected))
    except (ValueError, TypeError):
        raise HTTPException(403, "Signed organization selection required")
    target = request.path_params.get("organization_id")
    if request.method == "POST" and request.url.path.endswith(
        ("/authority/check", "/authority/billing-context")
    ):
        target = (await request.json()).get("organization_id") or target
    if target is not None and str(target) != str(selected):
        raise HTTPException(403, "Organization differs from signed selection")
    request.state.selected_organization = selected


router = APIRouter(dependencies=[Depends(selected_scope)])


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


class BillingQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    request_id: uuid.UUID
    tenant_id: uuid.UUID
    organization_id: uuid.UUID | None = None


@router.post("/authority/billing-context")
async def billing_context(
    body: BillingQuery,
    request: Request,
    response: Response,
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    from datetime import UTC, datetime
    from user_service.scoped_authority import actor_active

    if not enabled():
        raise HTTPException(503, "Scoped authority is not activated")
    if me.tenant_id != body.tenant_id or request.headers.get("X-Tenant-ID") != str(
        body.tenant_id
    ):
        raise HTTPException(403, "Billing context must match the verified tenant")
    if not await actor_active(session, body.tenant_id, me.sub):
        raise HTTPException(403, "Current active identity and tenant required")
    async with scope(session):
        identity = await session.scalar(
            text(
                "SELECT id FROM users WHERE tenant_id IS NULL AND keycloak_sub=:subject"
            ),
            {"subject": me.sub},
        )
    async with scope(session, body.tenant_id):
        rows = (
            (
                await session.execute(
                    text(
                        """SELECT m.organization_id FROM organization_memberships m
            JOIN users u ON u.id=m.user_id AND u.tenant_id=m.tenant_id
            JOIN organizations o ON o.id=m.organization_id AND o.tenant_id=m.tenant_id
            WHERE m.tenant_id=:tenant AND m.enabled AND m.can_purchase_leases
              AND u.keycloak_sub=:subject AND u.is_active AND u.deleted_at IS NULL
              AND (CAST(:org AS uuid) IS NULL OR m.organization_id=CAST(:org AS uuid))
            ORDER BY m.organization_id"""
                    ),
                    {
                        "tenant": body.tenant_id,
                        "subject": me.sub,
                        "org": body.organization_id
                        or getattr(request.state, "selected_organization", None),
                    },
                )
            )
            .scalars()
            .all()
        )
    if not rows:
        raise HTTPException(403, "Current organization billing membership required")
    if len(rows) != 1:
        raise HTTPException(409, "Select an authorized billing organization explicitly")
    response.headers["Cache-Control"] = "no-store"
    return {
        "version": 1,
        "request_id": str(body.request_id),
        "tenant_id": str(body.tenant_id),
        "subject": me.sub,
        "user_id": str(identity),
        "organization_id": str(rows[0]),
        "observed_at": datetime.now(UTC).isoformat(),
    }


class IdentityQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    request_id: uuid.UUID
    tenant_id: uuid.UUID


@router.post("/authority/identity-context")
async def identity_context(
    body: IdentityQuery,
    request: Request,
    response: Response,
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    from datetime import UTC, datetime
    from user_service.scoped_authority import (
        actor_active,
        tenant_network,
        network_admin,
    )

    if not enabled():
        raise HTTPException(503, "Scoped authority is not activated")
    if me.tenant_id != body.tenant_id or request.headers.get("X-Tenant-ID") != str(
        body.tenant_id
    ):
        raise HTTPException(403, "Identity context must match the verified tenant")
    if not await actor_active(session, body.tenant_id, me.sub):
        raise HTTPException(403, "Current active identity and tenant required")
    network = await tenant_network(session, body.tenant_id)
    administrative = await network_admin(session, network, me.sub)
    async with scope(session, body.tenant_id):
        member = await session.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=:tenant AND keycloak_sub=:subject AND is_active AND deleted_at IS NULL)"
            ),
            {"tenant": body.tenant_id, "subject": me.sub},
        )
    if not administrative and not member:
        raise HTTPException(403, "Current tenant identity required")
    async with scope(session):
        identity = await session.scalar(
            text(
                "SELECT id FROM users WHERE tenant_id IS NULL AND keycloak_sub=:subject"
            ),
            {"subject": me.sub},
        )
    response.headers["Cache-Control"] = "no-store"
    return {
        "version": 1,
        "request_id": str(body.request_id),
        "tenant_id": str(body.tenant_id),
        "subject": me.sub,
        "user_id": str(identity),
        "observed_at": datetime.now(UTC).isoformat(),
    }
