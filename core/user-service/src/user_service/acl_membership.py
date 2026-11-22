"""Resolve a single active membership for the private ACL owner."""
import hmac
import os
from uuid import UUID

from api.infrastructure.persistence.db_session import get_db_session
from controlplane_db.models import Group, User, UserGroupMembership
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

router = APIRouter(prefix="/internal/acl")


class MembershipLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: UUID
    group_id: UUID
    subject: str = Field(min_length=1, max_length=512)


@router.post("/group-membership")
async def lookup_membership(body: MembershipLookup, request: Request):
    secret = os.environ.get("ACL_MEMBERSHIP_LOOKUP_TOKEN", "")
    supplied = request.headers.get("authorization", "")
    if not secret:
        raise HTTPException(503, "ACL membership lookup is unconfigured")
    if not hmac.compare_digest(supplied.encode(), f"Bearer {secret}".encode()):
        raise HTTPException(401, "ACL membership credential required")
    if request.state.tenant_id != body.tenant_id:
        raise HTTPException(403, "Membership tenant mismatch")
    if not body.subject.strip() or any(ord(char) < 32 or ord(char) == 127 for char in body.subject):
        raise HTTPException(422, "Verified subject required")
    found = select(UserGroupMembership.id).join(
        User, User.id == UserGroupMembership.user_id,
    ).join(
        Group, Group.id == UserGroupMembership.group_id,
    ).where(
        UserGroupMembership.tenant_id == body.tenant_id,
        User.tenant_id == body.tenant_id,
        Group.tenant_id == body.tenant_id,
        User.keycloak_sub == body.subject,
        User.is_active.is_(True),
        User.deleted_at.is_(None),
        Group.id == body.group_id,
    )
    return {"member": bool(await get_db_session().scalar(select(found.exists())))}
