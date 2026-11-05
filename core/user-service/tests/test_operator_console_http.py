"""HTTP console gate. Does not open a database."""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import FastAPI

from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt
from user_service.interfaces.api.operator_routes import router


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return app


def _headers(permissions: list[str], *, roles: list[str] | None = None) -> dict[str, str]:
    tenant_id = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    token = mint_tenant_session_jwt(
        claims={
            "sub": "operator-1",
            "email": "op@example.com",
            "realm_access": {"roles": roles or ["admin"]},
            "groups": ["host"],
            "scope": "openid",
            "permissions": permissions,
        },
        tenant_id=tenant_id,
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": str(tenant_id),
    }


@pytest.fixture(autouse=True)
def _exchange_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from api.core import config as api_config

    monkeypatch.setattr(
        api_config.settings,
        "api_key_exchange_jwt_secret",
        "test-api-key-exchange-secret-min-32-chars!!",
    )


@pytest.mark.asyncio
async def test_session_requires_operator_console_claim():
    app = _app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        admin = await client.get(
            "/api/v1/operator/session",
            headers=_headers(["host:manage_tenants", "org:own"], roles=["admin"]),
        )
        assert admin.status_code == 403
        assert admin.json()["detail"] == "operator:console required"

        opened = await client.get(
            "/api/v1/operator/session",
            headers=_headers(["operator:console", "operator:support"]),
        )
        assert opened.status_code == 200, opened.text
        body = opened.json()
        assert body["operator_console"] is True
        assert body["operator_support"] is True
        assert body["operator_program"] is False
        assert "password" not in body


@pytest.mark.asyncio
async def test_ban_and_lift_do_not_return_a_mail_secret():
    app = _app()
    transport = httpx.ASGITransport(app=app)
    user_id = uuid.uuid4()
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/operator/bans",
            headers=_headers(["operator:console", "operator:support"]),
            json={
                "subject_kind": "user",
                "subject_id": str(user_id),
                "reason": "abuse",
                "email": "person@example.com",
            },
        )
        assert created.status_code == 201, created.text
        payload = created.json()
        assert payload["active"] is True
        assert payload["notice"]["sent"] is False
        assert payload["notice"]["detail"] == "message was not sent"
        blob = str(payload)
        assert "key-" not in blob
        assert "reset?" not in blob
        lifted = await client.post(
            f"/api/v1/operator/bans/{payload['id']}/lift",
            headers=_headers(["operator:console", "operator:support"]),
            json={"reason": "reviewed", "email": "person@example.com"},
        )
        assert lifted.status_code == 200, lifted.text
        assert lifted.json()["active"] is False


@pytest.mark.parametrize("path", ["audit", "directory/users"])
@pytest.mark.parametrize("permissions", [[], ["operator:console"], ["operator:support"]])
async def test_console_reads_require_both_console_and_support(path, permissions):
    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/operator/{path}", headers=_headers(permissions))
        assert response.status_code == 403, response.text


@pytest.mark.parametrize("query", ["limit=0", "limit=201", "offset=-1"])
async def test_audit_rejects_unbounded_or_negative_pagination(query):
    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/operator/audit?{query}",
                                    headers=_headers(["operator:console", "operator:support"]))
        assert response.status_code == 422, response.text


@pytest.mark.parametrize("path", ["audit", "directory/users"])
async def test_console_reads_refuse_cross_tenant_header(path):
    headers = _headers(["operator:console", "operator:support"])
    headers["X-Tenant-ID"] = str(uuid.uuid4())
    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/operator/{path}", headers=headers)
        assert response.status_code == 403, response.text


async def test_authorized_audit_reads_preserve_public_fields_and_page_metadata(monkeypatch):
    from api.domain.operator.audit import operator_audit
    from user_service.interfaces.api import operator_routes

    monkeypatch.setattr(operator_routes, "_db", lambda: None)
    headers = _headers(["operator:console", "operator:support"])
    operator_audit().clear()
    try:
        row = operator_audit().append(
            tenant_id=uuid.UUID(headers["X-Tenant-ID"]), actor="operator-1", action="role",
            target_kind="user", target_id=str(uuid.uuid4()), reason="reviewed",
        )
        transport = httpx.ASGITransport(app=_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/operator/audit?limit=1&offset=0", headers=headers)
            assert response.status_code == 200, response.text
            assert response.json() == {"items": [row.public()], "limit": 1, "offset": 0}
    finally:
        operator_audit().clear()


@pytest.mark.parametrize("permissions", [[], ["operator:console"], ["operator:support"]])
async def test_password_reset_requires_console_and_support(permissions):
    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/operator/mail/password-reset", headers=_headers(permissions),
                                     json={"user_id": str(uuid.uuid4()), "email": "person@example.com", "reason": "request"})
        assert response.status_code == 403
