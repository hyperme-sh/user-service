"""Private tenant ban fingerprint, computed by the owning User service."""
import hashlib
import json
import os
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from user_service.scope_api import service_caller

router = APIRouter()


class Query(BaseModel):
    model_config = ConfigDict(extra='forbid')
    tenant_id: UUID


class Digest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ban_hash: str
    computed_at: datetime


def fingerprint(tenant, rows):
    subjects = sorted({(str(kind), str(UUID(str(subject)))) for kind, subject in rows})
    if any(kind not in {'user', 'group', 'device'} for kind, _ in subjects):
        raise ValueError('Unknown ban subject kind')
    raw = json.dumps({'version': 1, 'tenant_id': str(UUID(str(tenant))), 'subjects': subjects},
                     sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return 'sha256-v1:' + hashlib.sha256(b'operator-active-bans-v1\0' + raw).hexdigest()


def allowed_tenants():
    try:
        values = json.loads(os.environ.get('PLANE_STATUS_TENANT_IDS', '[]'))
        if type(values) is not list or len(values) > 1024:
            raise ValueError()
        return {UUID(value) for value in values}
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(503, 'Invalid status tenant configuration') from None


@router.post('/internal/operator-bans/digest', response_model=Digest)
async def read_digest(body: Query, request: Request, response: Response,
                      caller: str = Depends(service_caller)):
    if caller != 'PLANE' or body.tenant_id not in allowed_tenants():
        raise HTTPException(403, 'Status tenant authority refused')
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    # A fresh owner transaction each read; failures never become an empty hash.
    async with request.app.state.session_maker() as db, db.begin():
        await db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),
                         {'tenant': str(body.tenant_id)})
        rows = (await db.execute(text(
            'SELECT subject_kind,subject_id FROM operator_bans '
            'WHERE tenant_id=:tenant AND lifted_at IS NULL'), {'tenant':body.tenant_id})).all()
        return Digest(ban_hash=fingerprint(body.tenant_id, rows), computed_at=datetime.now(UTC))
