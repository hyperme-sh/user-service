"""Fixed-route public forwarding; all closure authority stays in the private app."""

from __future__ import annotations

import httpx
from controlplane_identity.account_lifecycle import service_url
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from user_service.account_closure import (
    ClosureConfirmation,
    OperatorClosureConfirmation,
)
from user_service.closure_actions import HoldChange, enabled
from user_service.closure_directory import DirectoryUnavailable, native_response
from user_service.closure_transport import authority_verify
from user_service.lifecycle_read import (
    Permit,
    Principal,
    require_reader,
)

router = APIRouter(dependencies=[Depends(enabled)])
read_router = APIRouter(prefix="/internal/account-lifecycle", dependencies=[Depends(require_reader)])


async def forward(request, method, path, *, body=None, params=None, reader=False):
    headers = {}
    if reader:
        headers["X-Account-Lifecycle-Token"] = request.headers.get("X-Account-Lifecycle-Token", "")
        if "X-Tenant-ID" in request.headers:
            headers["X-Tenant-ID"] = request.headers["X-Tenant-ID"]
    else:
        # The private authority independently validates this original JWT. A
        # shared reader credential can never authorize closure or a hold change.
        headers["Authorization"] = request.headers.get("Authorization", "")
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=3, verify=authority_verify()) as client:
            code, value = await native_response(
                client, method, service_url("ACCOUNT_CLOSURE_AUTHORITY_URL") + "/api/v1" + path,
                headers=headers, json=body, params=params,
                max_bytes=16 * 1024 * 1024 if reader else 1024 * 1024,
            )
        if code not in {200, 202, 400, 401, 403, 404, 409, 422, 503} or not isinstance(value, dict):
            raise DirectoryUnavailable()
    except (DirectoryUnavailable, RuntimeError):
        raise HTTPException(503, "Account closure authority unavailable", headers={"Cache-Control": "no-store"}) from None
    return JSONResponse(status_code=code, content=value, headers={"Cache-Control": "no-store"})


@router.post("/me/account-closure", status_code=202)
async def close_self(body: ClosureConfirmation, request: Request):
    return await forward(request, "POST", "/me/account-closure", body=body.model_dump(mode="json"))


@router.post("/operator/account-closures", status_code=202)
async def close_account(body: OperatorClosureConfirmation, request: Request):
    return await forward(request, "POST", "/operator/account-closures", body=body.model_dump(mode="json"))


@router.get("/operator/account-closures")
async def closure_status(request: Request, subject: str = Query(min_length=1, max_length=512)):
    return await forward(request, "GET", "/operator/account-closures", params={"subject": subject})


@router.post("/operator/account-closures/hold")
async def change_hold(body: HoldChange, request: Request):
    return await forward(request, "POST", "/operator/account-closures/hold", body=body.model_dump(mode="json"))


@read_router.post("/check")
async def check(body: Principal, request: Request):
    return await forward(request, "POST", "/internal/account-lifecycle/check", body=body.model_dump(mode="json"), reader=True)


@read_router.post("/permit")
async def permit(body: Permit, request: Request):
    return await forward(request, "POST", "/internal/account-lifecycle/permit", body=body.model_dump(mode="json"), reader=True)


@read_router.get("/denials")
async def denials(request: Request):
    return await forward(request, "GET", "/internal/account-lifecycle/denials", reader=True)


@read_router.post("/scope")
async def scope(body: Permit, request: Request):
    return await forward(request, "POST", "/internal/account-lifecycle/scope", body=body.model_dump(mode="json"), reader=True)


@read_router.post("/grant-scope")
async def grant_scope(body: Permit, request: Request):
    return await forward(request, "POST", "/internal/account-lifecycle/grant-scope", body=body.model_dump(mode="json"), reader=True)


@read_router.post("/financial-scope")
async def financial_scope(body: Permit, request: Request):
    return await forward(request, "POST", "/internal/account-lifecycle/financial-scope", body=body.model_dump(mode="json"), reader=True)
