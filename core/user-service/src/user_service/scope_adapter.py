"""Auth's signed organization selection backed by the canonical authority graph.

The earlier identity_scope_* prototype is not mounted or provisioned. Preserve
its consumer DTO without creating a second set of grants or seed controller.
"""

import os
import uuid
from pydantic import BaseModel, ConfigDict, Field

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import text
from auth_service.deps import get_access_token_claims
from auth_service.schemas import AuthMeResponse
from user_service.deps import get_current_user

from user_service.scope_api import AuthorityBody, service_caller
from user_service.scoped_authority import (
    network_admin,
    organization_member,
    scope,
    tenant_network,
)

router = APIRouter()


def check_configuration():
    selected = os.environ.get("USER_SCOPE_GENERATION")
    if selected and (
        os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1"
        or selected != os.environ.get("USER_TEST_FIXTURE_GENERATION")
    ):
        raise RuntimeError(
            "Auth scope selection requires the canonical authority generation"
        )


@router.post(
    "/internal/organization-authority/check", dependencies=[Depends(service_caller)]
)
async def check(
    body: AuthorityBody,
    request: Request,
    response: Response,
    caller: str = Depends(service_caller),
):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        raise HTTPException(503, "Canonical authority is not active")
    if body.capability == "manage-members" and caller != "AUTH":
        raise HTTPException(403, "Service capability refused")
    if body.capability == "purchase" and caller not in ("PAYMENT", "PLANE"):
        raise HTTPException(403, "Service capability refused")
    if not body.subject.strip() or len(body.subject) > 512:
        raise HTTPException(422, "Verified subject required")
    async with request.app.state.session_maker() as db, db.begin():
        member = await organization_member(
            db, body.tenant_id, body.organization_id, body.subject
        )
        if (
            member is None
            or (body.capability == "manage-members" and member["role"] != "admin")
            or (body.capability == "purchase" and not member["can_purchase_leases"])
        ):
            return None
        network = await tenant_network(db, body.tenant_id)
        async with scope(db):
            uid = await db.scalar(
                text(
                    "SELECT id FROM users WHERE tenant_id IS NULL AND keycloak_sub=:subject"
                ),
                {"subject": body.subject},
            )
            seal = (
                await db.execute(
                    text(
                        "SELECT generation,manifest_sha256 FROM authority_fixture_generation"
                    )
                )
            ).one_or_none()
        if uid is None or seal is None:
            raise HTTPException(503, "Canonical generation is not sealed")
        return dict(
            subject=body.subject,
            user_id=uid,
            network_id=network,
            tenant_id=body.tenant_id,
            organization_id=body.organization_id,
            role=member["role"],
            can_purchase=member["can_purchase_leases"],
            generation=seal[0],
            manifest_sha256=seal[1],
        )


@router.get("/networks/{network_id}/authority")
async def network_authority(
    network_id: str,
    request: Request,
    response: Response,
    me: AuthMeResponse = Depends(get_current_user),
):
    response.headers["Cache-Control"] = "no-store"
    if os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        raise HTTPException(503, "Canonical authority is not active")
    async with request.app.state.session_maker() as db, db.begin():
        if not await network_admin(db, network_id, me.sub):
            raise HTTPException(403, "Current network authority required")
        async with scope(db):
            uid = await db.scalar(
                text(
                    "SELECT id FROM users WHERE tenant_id IS NULL AND keycloak_sub=:subject"
                ),
                {"subject": me.sub},
            )
            seal = (
                await db.execute(
                    text(
                        "SELECT generation,manifest_sha256 FROM authority_fixture_generation"
                    )
                )
            ).one_or_none()
        if uid is None or seal is None:
            raise HTTPException(503, "Canonical generation is not sealed")
        return dict(
            subject=me.sub,
            user_id=uid,
            network_id=network_id,
            tenant_id=None,
            organization_id=None,
            role="admin",
            can_purchase=False,
            generation=seal[0],
            manifest_sha256=seal[1],
        )


class NetworkQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=512)
    tenant_id: uuid.UUID


@router.post(
    "/internal/network-authority/check", dependencies=[Depends(service_caller)]
)
async def check_network(
    body: NetworkQuery,
    request: Request,
    response: Response,
    caller: str = Depends(service_caller),
):
    from user_service.scoped_authority import actor_active
    from user_service.identity_tenant_switch import authorize_tenant_switch

    if caller != "AUTH":
        raise HTTPException(403, "Auth scope credential required")
    if os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        raise HTTPException(503, "Canonical authority is not active")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    async with request.app.state.session_maker() as db, db.begin():
        if not await actor_active(db, body.tenant_id, body.subject):
            return None
        network = await tenant_network(db, body.tenant_id)
        if not await network_admin(db, network, body.subject):
            return None
        grant = await authorize_tenant_switch(
            AuthMeResponse(sub=body.subject), body.tenant_id, db
        )
        if grant is None or grant.role_name != "network-admin":
            return None
        async with scope(db):
            seal = (
                await db.execute(
                    text(
                        "SELECT generation,manifest_sha256 FROM authority_fixture_generation"
                    )
                )
            ).one_or_none()
        if seal is None:
            raise HTTPException(503, "Canonical generation is not sealed")
        return dict(
            subject=body.subject,
            user_id=grant.user_id,
            network_id=network,
            tenant_id=body.tenant_id,
            organization_id=None,
            role="admin",
            can_purchase=False,
            generation=seal[0],
            manifest_sha256=seal[1],
            permissions=list(grant.permissions),
        )


@router.post("/authority/login-tenant", status_code=204)
async def establish_login_tenant(
    request: Request, claims: dict = Depends(get_access_token_claims)
):
    """Create the individual profile for this deployment's portal login."""
    from user_service.scoped_authority import active_tenant

    destination = os.environ.get("USER_LOGIN_TENANT_ID")
    if not destination or os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        raise HTTPException(503, "Login tenant unavailable")
    tenant = uuid.UUID(destination)
    issuer = os.environ.get("KEYCLOAK_ISSUER")
    client = os.environ.get("USER_LOGIN_CLIENT_ID")
    subject = claims.get("sub")
    if (not issuer or not client or claims.get("iss") != issuer or claims.get("azp") != client
            or not isinstance(subject, str) or not subject or len(subject) > 512):
        raise HTTPException(403, "Portal identity required")
    async with request.app.state.session_maker() as db, db.begin():
        if not await active_tenant(db, tenant):
            raise HTTPException(403, "Login tenant inactive")
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:subject,0))"), {"subject": subject})
        async with scope(db):
            existing = (await db.execute(text(
                "SELECT is_active,deleted_at,sso_provider_id FROM users WHERE tenant_id IS NULL AND keycloak_sub=:sub FOR UPDATE"
            ), {"sub": subject})).one_or_none()
            if existing:
                if not existing.is_active or existing.deleted_at is not None:
                    raise HTTPException(403, "Account inactive")
                # Managed and legacy profiles retain their assigned destinations.
                if existing.sso_provider_id and existing.sso_provider_id != issuer:
                    raise HTTPException(403, "Account issuer differs")
                return Response(status_code=204)
        email = claims.get("email")
        if not isinstance(email, str) or not email.strip() or len(email) > 512 or claims.get("email_verified") is not True:
            raise HTTPException(403, "Verified contact required")
        for target in (None, tenant):
            async with scope(db, target):
                inserted = await db.scalar(text("""
                    INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,sso_provider_id)
                    VALUES(:id,:tenant,:sub,:email,:given,:family,'unspecified',true,:issuer)
                    ON CONFLICT DO NOTHING RETURNING id
                """), {"id": uuid.uuid4(), "tenant": target, "sub": subject, "email": email,
                       "given": str(claims.get("given_name") or "")[:255],
                       "family": str(claims.get("family_name") or "")[:255], "issuer": issuer})
                if inserted is None:
                    raise HTTPException(409, "Account reconciliation required")
    return Response(status_code=204)


@router.get("/authority/contexts")
async def contexts(
    request: Request, response: Response, me: AuthMeResponse = Depends(get_current_user)
):
    from user_service.scoped_authority import actor_active

    if os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        raise HTTPException(503, "Canonical authority is not active")
    response.headers["Cache-Control"] = "no-store"
    async with request.app.state.session_maker() as db, db.begin():
        # Tenant registry metadata is global, but only current configured
        # memberships or owned-network grants may expose a tenant to this actor.
        candidates = (
            await db.execute(
                text("SELECT id,name FROM tenants WHERE is_active ORDER BY id")
            )
        ).all()
        result = []
        for tenant, name in candidates:
            if not await actor_active(db, tenant, me.sub):
                continue
            network = await tenant_network(db, tenant)
            admin = await network_admin(db, network, me.sub)
            async with scope(db, tenant):
                member = await db.scalar(
                    text(
                        "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=:tenant AND keycloak_sub=:subject AND is_active AND deleted_at IS NULL)"
                    ),
                    {"tenant": tenant, "subject": me.sub},
                )
            if admin or member:
                result.append(
                    dict(id=tenant, name=name, network_id=network, network_admin=admin)
                )
        return {"tenants": result}
