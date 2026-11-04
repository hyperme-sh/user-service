"""Operator console API. Public branch: no Payments route.

Tenant comes from the session. Search and cases stay inside that tenant.
"""

from __future__ import annotations

from controlplane_api.config import settings

import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.domain.operator.audit import operator_audit
from api.domain.operator.bans import BanBook, BanError, NoUserSuspend, ban_book
from api.domain.operator.claims import (
    CONSOLE,
    PROGRAM,
    RESOLVE,
    SUPPORT,
    console_allowed,
    permissions_from_claims,
    program_may_edit_suite,
    support_allowed,
)
from api.domain.operator.mail import (
    MailForwarder,
    mail_quota,
    prepare_ban_notice,
    prepare_password_reset,
)
from api.domain.operator.peers import peer_book, ping_health
from controlplane_api.operator.plugins import plugin_by_id, plugin_registry
from api.infrastructure.persistence.db_session import get_db_session
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt

router = APIRouter(prefix="/operator", tags=["operator"])

CONSOLE_REQUIRED = "operator:console required"
SUPPORT_REQUIRED = "operator:support required"
PROGRAM_REQUIRED = "operator:program required"


class ReasonBody(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class BanBody(ReasonBody):
    subject_kind: str
    subject_id: uuid.UUID
    subject_label: str | None = None
    email: str | None = None


class LiftBody(ReasonBody):
    email: str | None = None


class MembershipBody(ReasonBody):
    group_name: str = Field(min_length=1, max_length=64)
    op: str = Field(pattern="^(add|remove)$")


class RoleBody(ReasonBody):
    role_id: uuid.UUID


class PeerBody(BaseModel):
    display_name: str = Field(min_length=1, max_length=256)
    base_url: str = Field(min_length=1, max_length=512)
    peer_tenant_id: str = Field(min_length=1, max_length=64)


class MailBody(ReasonBody):
    user_id: uuid.UUID
    email: str = Field(min_length=3, max_length=512)


def _bearer(request: Request) -> str | None:
    raw = request.headers.get("Authorization")
    if not raw:
        return None
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _session_claims(request: Request) -> dict:
    token = _bearer(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, CONSOLE_REQUIRED)
    claims = try_decode_tenant_session_jwt(token)
    if claims is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, CONSOLE_REQUIRED)
    header = request.headers.get("X-Tenant-ID")
    if not header:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Tenant-ID header is required")
    try:
        hdr = uuid.UUID(header)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid X-Tenant-ID") from exc
    claimed = claims.get("tenant_id") or claims.get("https://spanopticon.dev/tenant_id")
    if str(hdr) != str(claimed):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "X-Tenant-ID must match the session tenant")
    return claims


def require_console(request: Request) -> dict:
    claims = _session_claims(request)
    if not console_allowed(permissions_from_claims(claims), roles=claims.get("realm_access", {}).get("roles"), groups=claims.get("groups") if isinstance(claims.get("groups"), list) else None):
        raise HTTPException(status.HTTP_403_FORBIDDEN, CONSOLE_REQUIRED)
    return claims


def require_support(request: Request) -> dict:
    claims = require_console(request)
    if not support_allowed(permissions_from_claims(claims)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, SUPPORT_REQUIRED)
    return claims


def require_program(request: Request) -> dict:
    claims = require_console(request)
    if not program_may_edit_suite(permissions_from_claims(claims)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, PROGRAM_REQUIRED)
    return claims


def _tenant(claims: dict) -> uuid.UUID:
    return uuid.UUID(str(claims["tenant_id"]))


def _actor(claims: dict) -> str:
    return str(claims.get("sub") or "")


def _db() -> AsyncSession | None:
    try:
        return get_db_session()
    except RuntimeError:
        return None


def _audit(claims: dict, *, action: str, target_kind: str, target_id: str, reason: str, detail: dict[str, str] | None = None):
    row = operator_audit().append(
        tenant_id=_tenant(claims),
        actor=_actor(claims),
        action=action,
        target_kind=target_kind,
        target_id=target_id,
        reason=reason,
        detail=detail,
    )
    return row


async def _persist_audit(row) -> None:
    session = _db()
    if session is None:
        return
    from user_service.infrastructure.operator_store import insert_audit

    await insert_audit(session, row)


@router.get("/session")
async def operator_session(request: Request) -> dict:
    claims = require_console(request)
    perms = sorted(permissions_from_claims(claims))
    return {
        "tenant_id": str(_tenant(claims)),
        "sub": _actor(claims),
        "permissions": perms,
        "operator_console": CONSOLE in perms,
        "operator_support": SUPPORT in perms,
        "operator_program": PROGRAM in perms,
        "operator_resolve": RESOLVE in perms,
    }


@router.get("/plugins")
async def operator_plugins(request: Request) -> dict:
    require_console(request)
    return {"plugins": plugin_registry()}


@router.get("/plugins/{plugin_id}")
async def operator_plugin(request: Request, plugin_id: str) -> dict:
    require_console(request)
    row = plugin_by_id(plugin_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown plugin")
    return row


@router.get("/bans")
async def list_bans(
    request: Request,
    subject_kind: str | None = None,
    subject_id: uuid.UUID | None = None,
) -> dict:
    claims = require_support(request)
    tenant_id = _tenant(claims)
    session = _db()
    if session is not None:
        from user_service.infrastructure.operator_store import list_bans as stored_bans

        rows = await stored_bans(session, tenant_id, subject_kind=subject_kind,
                                 subject_id=subject_id)
    else:
        rows = [
            row
            for row in ban_book().rows
            if row.tenant_id == tenant_id
            and (subject_kind is None or row.subject_kind == subject_kind)
            and (subject_id is None or row.subject_id == subject_id)
        ]
    return {"items": [row.public() for row in rows]}


@router.post("/bans", status_code=status.HTTP_201_CREATED)
async def create_ban(request: Request, body: BanBody) -> dict:
    claims = require_support(request)
    session = _db()
    try:
        row = (BanBook() if session is not None else ban_book()).ban(
            tenant_id=_tenant(claims),
            subject_kind=body.subject_kind,
            subject_id=body.subject_id,
            reason=body.reason,
            created_by=_actor(claims),
            subject_label=body.subject_label,
        )
    except BanError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if session is not None:
        from user_service.infrastructure.operator_store import insert_ban

        try:
            await insert_ban(session, row)
        except BanError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit = _audit(
        claims,
        action="ban",
        target_kind=row.subject_kind,
        target_id=str(row.subject_id),
        reason=body.reason,
    )
    await _persist_audit(audit)
    notice = _maybe_notice(body.email, lifted=False, user_id=str(body.subject_id))
    if notice is not None and notice.sent:
        mail_audit = _audit(
            claims,
            action="mail",
            target_kind="user",
            target_id=str(body.subject_id),
            reason=body.reason,
            detail={"kind": "ban"},
        )
        await _persist_audit(mail_audit)
    return {**row.public(), "notice": None if notice is None else notice.public()}


@router.post("/bans/{ban_id}/lift")
async def lift_ban(request: Request, ban_id: uuid.UUID, body: LiftBody) -> dict:
    claims = require_support(request)
    session = _db()
    try:
        if session is not None:
            from user_service.infrastructure.operator_store import lift_ban as stored_lift

            row = await stored_lift(session, _tenant(claims), ban_id,
                                    lift_reason=body.reason, lifted_by=_actor(claims))
        else:
            row = ban_book().lift(
                tenant_id=_tenant(claims), ban_id=ban_id,
                lift_reason=body.reason, lifted_by=_actor(claims),
            )
    except BanError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    audit = _audit(
        claims,
        action="lift_ban",
        target_kind=row.subject_kind,
        target_id=str(row.subject_id),
        reason=body.reason,
    )
    await _persist_audit(audit)
    notice = _maybe_notice(body.email, lifted=True, user_id=str(row.subject_id))
    if notice is not None and notice.sent:
        mail_audit = _audit(
            claims,
            action="mail",
            target_kind="user",
            target_id=str(row.subject_id),
            reason=body.reason,
            detail={"kind": "lift"},
        )
        await _persist_audit(mail_audit)
    return {**row.public(), "notice": None if notice is None else notice.public()}


def _maybe_notice(email: str | None, *, lifted: bool, user_id: str):
    if not email:
        return None
    forwarder = MailForwarder.from_env(quota=mail_quota())
    message = prepare_ban_notice(email=email, lifted=lifted)
    return forwarder.send(message, user_id=user_id)


@router.post("/mail/password-reset")
async def password_reset(request: Request, body: MailBody) -> dict:
    """Prepare a reset on the server and send it through Mailgun.

    The response never includes the link. Unconfigured mail fails closed.
    """

    claims = require_support(request)
    action_url = (
        "https://spanopticon.internal/account/reset?token=" + secrets.token_urlsafe(32)
    )
    forwarder = MailForwarder.from_env(quota=mail_quota())
    message = prepare_password_reset(email=body.email, action_url=action_url)
    result = forwarder.send(message, user_id=str(body.user_id))
    del action_url
    if not result.sent:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {"sent": False, "detail": "message was not sent", "kind": "password_reset"},
        )
    audit = _audit(
        claims,
        action="mail",
        target_kind="user",
        target_id=str(body.user_id),
        reason=body.reason,
        detail={"kind": "password_reset"},
    )
    await _persist_audit(audit)
    return result.public()


@router.get("/audit")
async def list_audit(request: Request) -> dict:
    claims = require_console(request)
    if not support_allowed(permissions_from_claims(claims)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, SUPPORT_REQUIRED)
    rows = operator_audit().for_tenant(_tenant(claims))
    return {"items": [row.public() for row in rows]}


@router.get("/peers")
async def list_peers(request: Request) -> dict:
    claims = require_support(request)
    rows = peer_book().for_tenant(_tenant(claims))
    return {"items": [row.public() for row in rows]}


@router.post("/peers", status_code=status.HTTP_201_CREATED)
async def save_peer(request: Request, body: PeerBody) -> dict:
    claims = require_support(request)
    ok, detail = ping_health(body.base_url, fetch=_default_ping)
    row = peer_book().save(
        tenant_id=_tenant(claims),
        display_name=body.display_name,
        base_url=body.base_url,
        peer_tenant_id=body.peer_tenant_id,
        health_ok=ok,
        health_detail=detail,
    )
    session = _db()
    if session is not None:
        from user_service.infrastructure.operator_store import insert_peer

        await insert_peer(session, row)
    audit = _audit(
        claims,
        action="peer_save",
        target_kind="peer",
        target_id=str(row.id),
        reason=body.display_name,
        detail={"health": "up" if ok else "down"},
    )
    await _persist_audit(audit)
    return row.public()


def _default_ping(url: str) -> tuple[bool, str]:
    import httpx

    try:
        response = httpx.get(url, timeout=2.0)
    except httpx.HTTPError as exc:
        return False, str(exc)
    return response.status_code < 500, f"HTTP {response.status_code}"


@router.get("/networks/catalog")
async def catalog_health(request: Request) -> dict:
    """Catalog hop health. payments-access is not the Stripe case."""

    require_support(request)
    hops = [
        ("turn", "http://127.0.0.1:8012/health"),
        ("oracles", "http://127.0.0.1:8013/health"),
        ("payments-access", "http://127.0.0.1:8014/health"),
    ]
    cards = []
    for name, url in hops:
        ok, detail = ping_health(url.removesuffix("/health"), fetch=_default_ping)
        cards.append({"name": name, "url": url, "up": ok, "detail": detail})
    return {
        "hypermesh_url": settings.hypermesh_url,
        "catalog": cards,
        "stripe_case": False,
    }


@router.post("/users/{user_id}/soft-delete")
async def soft_delete_user(request: Request, user_id: uuid.UUID, body: ReasonBody) -> dict:
    """Soft-delete is not a ban and does not write operator_bans."""

    claims = require_support(request)
    session = _db()
    deleted_at = datetime.now(UTC).isoformat()
    if session is not None:
        from user_service.infrastructure.persistence.repos import SqlUserRepository

        ok = await SqlUserRepository(session).soft_delete(_tenant(claims), user_id)
        if not ok:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if ban_book().active_row(_tenant(claims), "user", user_id) is not None:
        pass
    audit = _audit(
        claims,
        action="soft_delete",
        target_kind="user",
        target_id=str(user_id),
        reason=body.reason,
    )
    await _persist_audit(audit)
    return {
        "user_id": str(user_id),
        "deleted_at": deleted_at,
        "banned": ban_book().active_row(_tenant(claims), "user", user_id) is not None,
    }


@router.post("/users/{user_id}/model-preference/clear")
async def clear_model_preference(request: Request, user_id: uuid.UUID, body: ReasonBody) -> dict:
    """Clear another user's model_name. Not a cert-suite edit."""

    claims = require_support(request)
    session = _db()
    if session is not None:
        from controlplane_tenancy.directory import clear_model_preference as clear_owned_preference

        await clear_owned_preference(session, _tenant(claims), user_id)
    audit = _audit(
        claims,
        action="clear_model_preference",
        target_kind="user",
        target_id=str(user_id),
        reason=body.reason,
    )
    await _persist_audit(audit)
    return {"user_id": str(user_id), "model_name": None}


@router.get("/directory/users")
async def directory_users(
    request: Request,
    q: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    claims = require_support(request)
    session = _db()
    if session is None:
        return {"items": [], "total": 0, "limit": limit, "offset": offset, "q": q}
    from user_service.infrastructure.persistence.repos import SqlUserRepository
    from user_service.interfaces.api.routes import _user_to_response

    users, total = await SqlUserRepository(session).list_active_paged(
        _tenant(claims), offset=offset, limit=limit, q=q
    )
    items = []
    for user in users:
        payload = _user_to_response(user).model_dump(mode="json")
        ban = ban_book().active_row(_tenant(claims), "user", user.id)
        payload["active_ban"] = None if ban is None else ban.public()
        payload["deleted_at"] = user.deleted_at.isoformat() if user.deleted_at else None
        items.append(payload)
    _audit(
        claims,
        action="lookup",
        target_kind="user",
        target_id=q or "*",
        reason="directory search",
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/directory/organizations")
async def directory_orgs(
    request: Request,
    q: str | None = Query(default=None, max_length=256),
) -> dict:
    claims = require_support(request)
    session = _db()
    if session is None:
        return {"items": [], "q": q}
    from user_service.infrastructure.persistence.repos import SqlOrganizationRepository

    orgs, _total = await SqlOrganizationRepository(session).list_paged(
        _tenant(claims), offset=0, limit=100, q=q
    )
    return {
        "items": [
            {"id": str(org.id), "legal_name": org.legal_name, "tenant_id": str(org.tenant_id)}
            for org in orgs
        ]
    }


@router.post("/users/{user_id}/membership")
async def edit_membership(request: Request, user_id: uuid.UUID, body: MembershipBody) -> dict:
    claims = require_support(request)
    session = _db()
    if session is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "directory store unavailable")
    from user_service.infrastructure.persistence.repos import (
        SqlMembershipRepository, SqlUserRepository, SqlGroupRepository,
    )

    tenant_id = _tenant(claims)
    user = await SqlUserRepository(session).get(tenant_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    group = await SqlGroupRepository(session).get_by_name(tenant_id, body.group_name)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")
    membership = SqlMembershipRepository(session)
    if body.op == "add":
        if not await membership.exists(tenant_id, user_id, group.id):
            await membership.add(tenant_id, user_id, group.id)
    else:
        await membership.remove(tenant_id, user_id, group.id)
    audit = _audit(
        claims,
        action="membership",
        target_kind="user",
        target_id=str(user_id),
        reason=body.reason,
        detail={"group": body.group_name, "op": body.op},
    )
    await _persist_audit(audit)
    return {"user_id": str(user_id), "group": body.group_name, "op": body.op}


@router.post("/users/{user_id}/role")
async def edit_role(request: Request, user_id: uuid.UUID, body: RoleBody) -> dict:
    claims = require_support(request)
    session = _db()
    if session is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "directory store unavailable")
    from user_service.infrastructure.persistence.repos import SqlUserRepository

    updated = await SqlUserRepository(session).set_role(_tenant(claims), user_id, body.role_id)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    audit = _audit(
        claims,
        action="role",
        target_kind="user",
        target_id=str(user_id),
        reason=body.reason,
        detail={"role_id": str(body.role_id)},
    )
    await _persist_audit(audit)
    return {"user_id": str(user_id), "role_id": str(body.role_id)}


@router.post("/suspend")
async def record_suspend(request: Request) -> dict:
    """Temporary verbs only. This route never writes operator_bans."""

    claims = require_support(request)
    body = await request.json()
    kind = str(body.get("subject_kind") or "")
    verb = str(body.get("verb") or "")
    subject_id = str(body.get("subject_id") or "")
    reason = str(body.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "reason is required")
    before = len(ban_book().rows)
    try:
        entry = ban_book().suspend(subject_kind=kind, verb=verb, subject_id=subject_id)
    except NoUserSuspend as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except BanError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if len(ban_book().rows) != before:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "suspend wrote a ban")
    audit = _audit(
        claims,
        action="suspend",
        target_kind=kind,
        target_id=subject_id,
        reason=reason,
        detail={"verb": verb},
    )
    await _persist_audit(audit)
    return {"suspend": entry, "ban_rows": len(ban_book().rows)}
