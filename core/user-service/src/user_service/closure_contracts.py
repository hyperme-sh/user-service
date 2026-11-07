"""Public closure request contracts and gates; no private persistence imports."""
from __future__ import annotations
import os
import uuid
from datetime import datetime
from typing import Literal
from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from controlplane_identity.account_lifecycle import authorized_call, enforcement_enabled

class ClosureConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: Literal["CLOSE MY ACCOUNT"]


class OperatorClosureConfirmation(ClosureConfirmation):
    subject: str = Field(min_length=1, max_length=512)

def enabled(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    if os.environ.get("ACCOUNT_CLOSURE_ACTIONS_ENABLED", "").lower() != "true" or not enforcement_enabled():
        raise HTTPException(503, "Account closure actions are not enabled", headers={"Cache-Control": "no-store"})

class HoldChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=512)
    hold: bool = Field(strict=True)
    reference: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

def require_reader(request: Request, response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    if not authorized_call(request.headers):
        raise HTTPException(403, "Account lifecycle authority required")

class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=512)
    tenant_id: uuid.UUID | None = None


class Permit(Principal):
    closed_at: datetime
