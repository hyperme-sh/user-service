"""Pending closure requests; no identity or retention side effects at intake."""
from __future__ import annotations

from user_service.closure_contracts import ClosureConfirmation, OperatorClosureConfirmation

import asyncio
import os
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from api.infrastructure.persistence.db_session import get_db_session
from auth_service.schemas import AuthMeResponse
from user_service.deps import get_current_user, require_matched_tenant
from user_service.infrastructure.persistence.repos import SqlUserRepository
from user_service.interfaces.api.operator_routes import require_support, _tenant, _actor
from user_service.models import AccountClosureRequest

def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(tags=["Account closure requests"], dependencies=[Depends(no_store)])


class ClosureRequestStatus(BaseModel):
    subject: str
    requested_at: datetime
    source: Literal["self_service", "operator"]
    state: Literal["pending"] = "pending"


def require_intake_enabled() -> None:
    # Keep off until sign-in/key revocation and deletion workers are integrated.
    if os.environ.get("ACCOUNT_CLOSURE_REQUESTS_ENABLED", "").lower() != "true":
        raise HTTPException(503, "Account closure request intake is not enabled")


def valid_subject(subject: str) -> str:
    # Do not normalize opaque IdP subject identifiers or fall back to email/id.
    if not subject or not subject.strip() or len(subject) > 512:
        raise HTTPException(422, "An exact account subject is required")
    return subject


async def find_request(session: AsyncSession, tenant: uuid.UUID, subject: str):
    return (await session.execute(select(AccountClosureRequest).where(
        AccountClosureRequest.tenant_id == tenant,
        AccountClosureRequest.subject == subject,
    ))).scalar_one_or_none()


def response(row: AccountClosureRequest) -> ClosureRequestStatus:
    return ClosureRequestStatus(subject=row.subject, requested_at=row.requested_at, source=row.source)


async def record_request(session: AsyncSession, tenant: uuid.UUID, subject: str,
                         actor: str, source: Literal["self_service", "operator"]):
    valid_subject(subject)
    valid_subject(actor)
    existing = await find_request(session, tenant, subject)
    if existing is not None:
        return response(existing)
    user = await SqlUserRepository(session).get_by_keycloak_sub(tenant, subject)
    if user is None or not user.is_active:
        raise HTTPException(404, "Active account not found")
    # A unique tenant/subject insert serializes concurrent self/operator retries.
    # First request timestamp and provenance survive retries and process restarts.
    await session.execute(insert(AccountClosureRequest).values(
        tenant_id=tenant, subject=subject, requested_at=datetime.now(UTC),
        requested_by=actor, source=source,
    ).on_conflict_do_nothing(index_elements=["tenant_id", "subject"]))
    return response(await find_request(session, tenant, subject))


@router.post("/me/account-closure-request", response_model=ClosureRequestStatus, status_code=202,
             openapi_extra={"security": [{"BearerAuth": []}]})
async def request_own_closure(
    body: ClosureConfirmation,
    tenant: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    require_intake_enabled()
    return await record_request(session, tenant, me.sub, me.sub, "self_service")


@router.get("/me/account-closure-request", response_model=ClosureRequestStatus,
            openapi_extra={"security": [{"BearerAuth": []}]})
async def own_closure_status(
    tenant: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    row = await find_request(session, tenant, valid_subject(me.sub))
    if row is None:
        raise HTTPException(404, "Account closure request not found")
    return response(row)


@router.post("/operator/account-closure-requests", response_model=ClosureRequestStatus, status_code=202)
async def request_operator_closure(
    request: Request, body: OperatorClosureConfirmation,
    session: AsyncSession = Depends(get_db_session),
):
    claims = await asyncio.to_thread(require_support, request)
    require_intake_enabled()
    return await record_request(session, _tenant(claims), body.subject, _actor(claims), "operator")


@router.get("/operator/account-closure-requests", response_model=ClosureRequestStatus)
async def operator_closure_status(
    request: Request, subject: str = Query(min_length=1, max_length=512),
    session: AsyncSession = Depends(get_db_session),
):
    claims = await asyncio.to_thread(require_support, request)
    row = await find_request(session, _tenant(claims), valid_subject(subject))
    if row is None:
        raise HTTPException(404, "Account closure request not found")
    return response(row)
