"""Default-off native account actions; pending intake never executes implicitly."""
from __future__ import annotations

from user_service.closure_contracts import HoldChange, enabled

import json
import os
from datetime import datetime
from typing import Literal

import httpx
from controlplane_identity.account_lifecycle import enforcement_enabled
from controlplane_identity.security.keycloak_jwt import get_keycloak_jwt_validator
from controlplane_tenancy.tenant_membership import identity_retired_at, lock_identity
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from jwt import InvalidTokenError, PyJWKClientError
from pydantic import BaseModel, ConfigDict, Field

from user_service.account_closure import (
    ClosureConfirmation,
    OperatorClosureConfirmation,
)
from user_service.closure_authorization import account_subject, global_closure_operator
from user_service.closure_directory import (
    DirectoryNotFound,
    DirectoryUnavailable,
    KeycloakClosureReader,
    ProtectedIdentity,
)
from user_service.closure_jobs import ClosureJobs
from user_service.models import AccountLifecycle


router = APIRouter(tags=["Account closure"], dependencies=[Depends(enabled)])


class LifecycleStatus(BaseModel):
    subject: str
    state: Literal["closing", "closed", "deleting", "deleted"]
    requested_at: datetime
    source: Literal["self_service", "operator"]
    closed_at: datetime | None
    profile_deleted_at: datetime | None
    financial_deleted_at: datetime | None
    financial_hold: bool


def status(row: AccountLifecycle) -> LifecycleStatus:
    return LifecycleStatus(**{key: getattr(row, key) for key in LifecycleStatus.model_fields})


def jobs(request: Request) -> ClosureJobs:
    store = ClosureJobs(request.app.state.closure_session_maker)
    store.directory = getattr(request.app.state, "closure_directory", None)
    return store


def bearer(request: Request) -> str:
    value = request.headers.get("Authorization", "")
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token or any(char.isspace() for char in token):
        raise HTTPException(401, "Native account token required", headers={"Cache-Control": "no-store"})
    return token


async def operator(request: Request) -> str:
    try:
        configured = json.loads(os.environ.get("ACCOUNT_CLOSURE_OPERATOR_CLIENT_IDS", "[]"))
        if (not isinstance(configured, list) or not configured or len(configured) > 1000
                or any(not isinstance(value, str) or not value.strip() for value in configured)
                or len(set(configured)) != len(configured)):
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(503, "Closure operator trust is not configured", headers={"Cache-Control": "no-store"}) from None
    try:
        claims = await get_keycloak_jwt_validator().validate_closure_operator(
            bearer(request), client_ids=frozenset(configured),
        )
    except (InvalidTokenError, PyJWKClientError):
        raise HTTPException(401, "Native closure operator token required", headers={"Cache-Control": "no-store"}) from None
    return global_closure_operator(claims)


async def read_status(store: ClosureJobs, subject: str) -> LifecycleStatus | None:
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        if row is not None and (type(row.effects.get("processor_version")) is not int or row.effects["processor_version"] != 1):
            raise HTTPException(409, "Legacy closure requires explicit reconciliation", headers={"Cache-Control": "no-store"})
        if row is None and await identity_retired_at(session, subject) is not None:
            raise HTTPException(409, "Legacy closure requires explicit reconciliation", headers={"Cache-Control": "no-store"})
        return status(row) if row is not None else None


async def submit(store: ClosureJobs, subject: str, actor: str, source: str) -> LifecycleStatus:
    # Close this transaction before provider I/O. Retried roots remain readable
    # after native identity deletion; a missing provider account creates no root.
    existing = await read_status(store, subject)
    if existing is not None:
        return existing
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=3) as client:
            directory = getattr(store, "directory", None)
            if directory is None:
                directory = KeycloakClosureReader(client)
            await directory.lookup(subject)
    except DirectoryNotFound:
        raise HTTPException(404, "Native account not found", headers={"Cache-Control": "no-store"}) from None
    except ProtectedIdentity:
        raise HTTPException(403, "Protected account cannot be closed", headers={"Cache-Control": "no-store"}) from None
    except (DirectoryUnavailable, RuntimeError):
        raise HTTPException(503, "Native identity preflight unavailable", headers={"Cache-Control": "no-store"}) from None
    try:
        await store.request(subject, actor, source)
    except ValueError:
        raise HTTPException(409, "Legacy closure requires explicit reconciliation", headers={"Cache-Control": "no-store"}) from None
    result = await read_status(store, subject)
    if result is None:
        raise HTTPException(503, "Account closure unavailable", headers={"Cache-Control": "no-store"})
    return result


@router.post("/me/account-closure", status_code=202, response_model=LifecycleStatus)
async def close_self(body: ClosureConfirmation, request: Request):
    try:
        claims = await get_keycloak_jwt_validator().validate(bearer(request))
    except (InvalidTokenError, PyJWKClientError):
        raise HTTPException(401, "Native account token required", headers={"Cache-Control": "no-store"}) from None
    subject = account_subject(claims)
    return await submit(jobs(request), subject, subject, "self_service")


@router.post("/operator/account-closures", status_code=202, response_model=LifecycleStatus)
async def close_account(body: OperatorClosureConfirmation, request: Request):
    actor = await operator(request)
    return await submit(jobs(request), body.subject, actor, "operator")


@router.get("/operator/account-closures", response_model=LifecycleStatus)
async def closure_status(request: Request, subject: str = Query(min_length=1, max_length=512)):
    await operator(request)
    result = await read_status(jobs(request), subject)
    if result is None:
        raise HTTPException(404, "Account closure not found", headers={"Cache-Control": "no-store"})
    return result


@router.post("/operator/account-closures/hold", response_model=LifecycleStatus)
async def change_hold(body: HoldChange, request: Request):
    await operator(request)
    async with jobs(request).transaction() as session:
        # Match worker lock order; the native trigger alone obtains this lock
        # after its target row, which can invert against identity-first erasure.
        await lock_identity(session, body.subject)
        row = await session.get(AccountLifecycle, body.subject, with_for_update=True)
        if row is None:
            raise HTTPException(404, "Account closure not found", headers={"Cache-Control": "no-store"})
        if not body.hold and row.financial_hold and row.hold_reference != body.reference:
            raise HTTPException(409, "The current hold reference is required", headers={"Cache-Control": "no-store"})
        if body.hold and row.financial_hold and row.hold_reference != body.reference:
            raise HTTPException(409, "Release the current hold explicitly first", headers={"Cache-Control": "no-store"})
        row.financial_hold = body.hold
        row.hold_reference = body.reference if body.hold else None
        await session.flush()
        return status(row)
