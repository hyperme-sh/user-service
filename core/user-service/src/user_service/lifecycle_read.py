"""Private, read-only account retirement authority. No JWT dependency recursion."""

from __future__ import annotations

import uuid
from datetime import datetime

import httpx
from api.infrastructure.persistence.db_session import get_db_session
from controlplane_db.models import IdentityRetirement
from controlplane_identity.account_lifecycle import (
    authorized_call,
    service_secret,
    service_url,
)
from controlplane_tenancy.tenant_membership import identity_retired_at
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from user_service.models import AccountLifecycle, AccountLifecycleScope


def require_reader(request: Request, response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers):
        raise HTTPException(403, "Account lifecycle authority required")


router = APIRouter(
    prefix="/internal/account-lifecycle",
    tags=["Internal account lifecycle"],
    dependencies=[Depends(require_reader)],
)


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=512)
    tenant_id: uuid.UUID | None = None


class Permit(Principal):
    closed_at: datetime


async def key_blocked(principal: Principal) -> bool:
    # Exchange sessions can wrap API-key subjects. Do not accept a missing key,
    # missing tenant, nested key owner, unavailable owner, or non-boolean reply.
    try:
        identifier = uuid.UUID(principal.subject.removeprefix("apikey:"))
        if principal.tenant_id is None:
            return True
        async with httpx.AsyncClient(
            timeout=3, trust_env=False, follow_redirects=False
        ) as client:
            response = await client.post(
                service_url("ACCOUNT_CLOSURE_KEYS_URL")
                + "/api/v1/api-keys/internal/account-status",
                headers={
                    "X-Account-Lifecycle-Token": service_secret(
                        "ACCOUNT_CLOSURE_GUARD_TOKEN"
                    ),
                    "X-Tenant-ID": str(principal.tenant_id),
                },
                json={"key_id": str(identifier)},
            )
        result = response.json() if response.status_code == 200 else None
        return not (isinstance(result, dict) and result.get("blocked") is False)
    except Exception:
        return True


@router.post("/check")
async def check(principal: Principal, session: AsyncSession = Depends(get_db_session)):
    if principal.subject.startswith("apikey:"):
        blocked = await key_blocked(principal)
    else:
        blocked = (
            not principal.subject.strip()
            or await session.get(AccountLifecycle, principal.subject) is not None
            or await identity_retired_at(session, principal.subject) is not None
        )
    return {"blocked": blocked}


@router.post("/permit")
async def permit(body: Permit, session: AsyncSession = Depends(get_db_session)):
    # This is evidence for owner effects, not permission to choose an arbitrary
    # timestamp/tenant with only a generic mutation credential.
    row = await session.get(AccountLifecycle, body.subject)
    allowed = (
        row is not None
        and row.closed_at is not None
        and body.closed_at.tzinfo is not None
        and row.closed_at == body.closed_at
    )
    if allowed and body.tenant_id is not None:
        allowed = (
            await session.execute(
                select(AccountLifecycleScope.subject).where(
                    AccountLifecycleScope.tenant_id == body.tenant_id,
                    AccountLifecycleScope.subject == body.subject,
                )
            )
        ).scalar_one_or_none() is not None
    return {"allowed": bool(allowed)}


@router.get("/denials")
async def denials(request: Request, session: AsyncSession = Depends(get_db_session)):
    from controlplane_identity.account_lifecycle import key_digest, subject_digest

    tenant = getattr(request.state, "tenant_id", None)
    if tenant is None:
        raise HTTPException(400, "X-Tenant-ID required")
    # This must be a complete snapshot, never a silently truncated page. A
    # closing principal whose scope discovery/inventory is pending prevents a
    # new gateway bootstrap; existing durable local denials remain usable.
    # A retirement without its original lifecycle inventory also blocks a
    # complete snapshot. Do not mint an empty root or silently omit it.
    rows = (
        await session.execute(
            select(AccountLifecycle.subject, AccountLifecycle.effects)
            .select_from(AccountLifecycle)
            .join(
                IdentityRetirement,
                IdentityRetirement.subject == AccountLifecycle.subject,
                full=True,
            )
            .order_by(AccountLifecycle.subject)
            .limit(100_001)
        )
    ).all()
    if len(rows) > 100_000 or any(
        not isinstance(row.effects, dict)
        or row.effects.get("scope_discovery") is not True
        for row in rows
    ):
        raise HTTPException(503, "Account denial inventory incomplete")
    scopes = (
        (
            await session.execute(
                select(AccountLifecycleScope)
                .where(AccountLifecycleScope.tenant_id == tenant)
                .limit(100_001)
            )
        )
        .scalars()
        .all()
    )
    if len(scopes) > 100_000:
        raise HTTPException(503, "Account denial inventory exceeds snapshot limit")
    subjects = [subject_digest(tenant, row.subject) for row in rows]
    keys, fingerprints, leases = set(), set(), set()
    try:
        for scope in scopes:
            key_receipt = scope.effects["api_keys"]
            lease_receipt = scope.effects["hypermesh"]
            for key in key_receipt["keys"]:
                keys.add(key_digest(tenant, uuid.UUID(key["id"])))
                if key.get("fingerprint"):
                    fingerprints.add(key["fingerprint"])
            for lease in lease_receipt["lease_ids"]:
                leases.add(str(uuid.UUID(lease)))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise HTTPException(503, "Account denial inventory incomplete") from None
    if len(subjects) + len(keys) + len(fingerprints) + len(leases) > 100_000:
        raise HTTPException(503, "Account denial inventory exceeds snapshot limit")
    return {
        "version": 1,
        "complete": True,
        "subjects": subjects,
        "keys": sorted(keys),
        "fingerprints": sorted(fingerprints),
        "leases": sorted(leases),
    }


@router.post("/scope")
async def scope(
    body: Permit, request: Request, session: AsyncSession = Depends(get_db_session)
):
    """Canonical committed inventory; mutation receivers cannot choose owners."""
    from datetime import UTC

    from controlplane_tenancy.account_profile import _closure_retention

    if (
        body.tenant_id is None
        or getattr(request.state, "tenant_id", None) != body.tenant_id
    ):
        return {"allowed": False}
    row = await session.get(AccountLifecycle, body.subject, populate_existing=True)
    if (
        row is None
        or row.closed_at is None
        or body.closed_at.tzinfo is None
        or row.closed_at != body.closed_at
    ):
        return {"allowed": False}
    from controlplane_tenancy.tenant_membership import identity_retired_at

    retirement = await identity_retired_at(session, body.subject)
    if retirement is None or retirement > body.closed_at:
        return {"allowed": False}
    registered = await session.get(
        AccountLifecycleScope, (body.tenant_id, body.subject), populate_existing=True
    )
    if (
        registered is None
        or registered.effects.get("profile_inventory_complete") is not True
    ):
        return {"allowed": False}
    from controlplane_tenancy.directory import SqlUserRepository

    renter_ids = list(registered.user_ids)
    ambiguous = False
    try:
        alias = uuid.UUID(body.subject)
    except ValueError:
        alias = None
    if alias is not None and str(alias) not in renter_ids:
        existing = await SqlUserRepository(session).get_any(body.tenant_id, alias)
        if existing is None:
            renter_ids.append(str(alias))
        else:
            # A legacy UUID fallback cannot claim another directory person's
            # row. Keep the account incomplete until ownership is proved.
            ambiguous = True
    receipt = registered.effects.get("api_keys")
    complete = isinstance(receipt, dict) and isinstance(receipt.get("keys"), list)
    return {
        "allowed": True,
        "user_ids": registered.user_ids,
        "renter_ids": renter_ids,
        "renter_alias_ambiguous": ambiguous,
        "keys": receipt["keys"] if complete else [],
        "keys_complete": complete,
        "erasure_allowed": (
            not ambiguous
            and row.state in {"closed", "deleting", "deleted"}
            and datetime.now(UTC) >= row.closed_at + _closure_retention()
            and row.effects.get("scope_discovery") is True
            and complete
        ),
    }


@router.post("/grant-scope")
async def grant_scope(
    body: Permit, request: Request, session: AsyncSession = Depends(get_db_session)
):
    """Frozen native grants for this closing account, never caller-chosen denials."""
    import re

    proof = await scope(body, request, session)
    if (
        proof.get("allowed") is not True
        or proof.get("keys_complete") is not True
        or proof.get("renter_alias_ambiguous") is not False
    ):
        return {"allowed": False}
    registered = await session.get(
        AccountLifecycleScope, (body.tenant_id, body.subject)
    )
    native = registered.effects.get("hypermesh")
    if (
        not isinstance(native, dict)
        or native.get("tickets_revoked") is not True
        or native.get("new_selling_disabled") is not True
    ):
        return {"allowed": False}
    leases = native.get("lease_ids")
    keys = proof["keys"]
    if not isinstance(leases, list) or len(leases) + len(keys) > 100_000:
        return {"allowed": False}
    try:
        lease_ids = [str(uuid.UUID(value)) for value in leases]
        key_ids, fingerprints = [], []
        for key in keys:
            key_ids.append(str(uuid.UUID(key["id"])))
            fingerprint = key.get("fingerprint")
            if fingerprint is not None:
                if (
                    not isinstance(fingerprint, str)
                    or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
                ):
                    return {"allowed": False}
                fingerprints.append(fingerprint)
        if len(set(lease_ids)) != len(lease_ids) or len(set(key_ids)) != len(key_ids):
            return {"allowed": False}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"allowed": False}
    return {
        "allowed": True,
        "key_ids": sorted(key_ids),
        "fingerprints": sorted(set(fingerprints)),
        "lease_ids": sorted(lease_ids),
    }


@router.post("/financial-scope")
async def financial_scope(
    body: Permit, request: Request, session: AsyncSession = Depends(get_db_session)
):
    """Frozen payer identities survive personal erasure; no contact lookup."""
    if getattr(request.state, "tenant_id", None) != body.tenant_id:
        return {"allowed": False}
    row = await session.get(AccountLifecycle, body.subject, populate_existing=True)
    if (
        row is None
        or row.state not in {"closed", "deleting", "deleted"}
        or row.closed_at is None
        or body.closed_at.tzinfo is None
        or body.closed_at != row.closed_at
        or row.effects.get("identity", {}).get("disabled") is not True
    ):
        return {"allowed": False}
    if body.tenant_id is not None:
        proof = await scope(body, request, session)
        if (
            proof.get("allowed") is not True
            or proof["renter_alias_ambiguous"]
            or proof["keys_complete"] is not True
        ):
            return {"allowed": False}
        identifiers = proof["user_ids"]
        keys = proof["keys"]
    else:
        from controlplane_tenancy.tenant_membership import identity_retired_at

        retired = await identity_retired_at(session, body.subject)
        if retired is None or retired > row.closed_at:
            return {"allowed": False}
        profile = row.effects.get("platform_profile")
        if not isinstance(profile, dict):
            return {"allowed": False}
        identifiers = profile.get("user_ids")
        keys = []
    try:
        if not isinstance(identifiers, list) or len(identifiers) > 100_000:
            raise ValueError()
        if not isinstance(keys, list) or len(keys) > 100_000:
            raise ValueError()
        key_ids = sorted({str(uuid.UUID(key["id"])) for key in keys})
        if len(key_ids) != len(keys):
            raise ValueError()
        canonical = sorted({str(uuid.UUID(value)) for value in identifiers})
        if len(canonical) != len(identifiers):
            raise ValueError()
    except (TypeError, ValueError, AttributeError, KeyError):
        raise HTTPException(503, "Financial identity inventory incomplete") from None
    return {
        "allowed": True,
        "user_ids": canonical,
        "key_ids": key_ids,
        "financial_hold": row.financial_hold,
    }
