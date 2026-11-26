"""Consolidated scope routes use the canonical graph, not prototype grants."""

import uuid
import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from auth_service.deps import get_access_token_claims
from auth_service.schemas import AuthMeResponse
from user_service.deps import get_current_user
from user_service.scoped_authority import scope
from test_fixture_bootstrap import bootstrap, ISSUER, MANIFEST


async def test_production_scope_routes_and_network_context_revocation(
    empty_authority_owner, monkeypatch
):
    from user_service.app import create_app

    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    monkeypatch.setenv("USER_TEST_FIXTURE_GENERATION", MANIFEST["generation"])
    monkeypatch.setenv("USER_SCOPE_GENERATION", MANIFEST["generation"])
    for caller in ("AUTH", "PAYMENT", "PLANE"):
        monkeypatch.setenv(caller + "_SCOPE_AUTHORITY_TOKEN", "isolated-" + caller)
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)
    app = create_app(test_event_sink=[])
    app.state.session_maker = maker
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    actor = "network-admin"

    async def me():
        return AuthMeResponse(sub=accounts[actor]["id"], tenant_id=tenant)

    app.dependency_overrides[get_current_user] = me
    body = dict(subject=accounts["network-admin"]["id"], tenant_id=str(tenant))
    path = "/api/v1/internal/network-authority/check"
    headers = {"Authorization": "Bearer isolated-AUTH"}
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://local"
        ) as client:
            result = await client.post(path, headers=headers, json=body)
            assert result.status_code == 200, result.text
            assert result.json()["user_id"] == body["subject"]
            assert result.json()["organization_id"] is None
            assert result.json()["can_purchase"] is False
            assert "operator:program" in result.json()["permissions"]
            assert result.headers["cache-control"] == "no-store"
            for fixture in (
                "primary-admin",
                "wrongadmin",
                "s3r-network-admin",
                "tw-network-admin",
                "disabled-member",
                "unassociated",
            ):
                denied = await client.post(
                    path,
                    headers=headers,
                    json={**body, "subject": accounts[fixture]["id"]},
                )
                assert denied.status_code == 200 and denied.json() is None
            for credential in ("isolated-PAYMENT", "isolated-PLANE", "wrong"):
                denied = await client.post(
                    path, headers={"Authorization": "Bearer " + credential}, json=body
                )
                assert denied.status_code == (401 if credential == "wrong" else 403)
            for fixture, expected in [
                ("network-admin", 1),
                ("host-owner", 1),
                ("unassociated", 1),
                ("wrongadmin", 0),
                ("disabled-member", 0),
                ("s3r-network-admin", 0),
            ]:
                actor = fixture
                result = await client.get("/api/v1/authority/contexts")
                assert result.status_code == 200, result.text
                assert len(result.json()["tenants"]) == expected
                if expected:
                    assert result.json()["tenants"][0]["network_admin"] == (
                        fixture == "network-admin"
                    )
            actor = "network-admin"
            for network in ("hyperme.sh", "s3r.ch", "tennesseewindage"):
                result = await client.get("/api/v1/networks/" + network + "/authority")
                assert result.status_code == (
                    200 if network == "hyperme.sh" else 403
                ), result.text
            async with maker() as db, db.begin(), scope(db, network="hyperme.sh"):
                await db.execute(
                    text(
                        "UPDATE authority_network_admins SET enabled=false WHERE user_id=:user"
                    ),
                    {"user": uuid.UUID(body["subject"])},
                )
            denied = await client.post(path, headers=headers, json=body)
            assert denied.status_code == 200 and denied.json() is None
            assert (await client.get("/api/v1/authority/contexts")).json() == {
                "tenants": []
            }
            assert (
                await client.get("/api/v1/networks/hyperme.sh/authority")
            ).status_code == 403
    finally:
        await engine.dispose()


async def test_native_organization_discovery_checks_current_membership(empty_authority_owner, monkeypatch):
    from user_service.app import create_app

    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    monkeypatch.setenv("KEYCLOAK_ISSUER", ISSUER)
    engine = create_async_engine(empty_authority_owner.url.set(drivername="postgresql+asyncpg"))
    maker = async_sessionmaker(engine)
    app = create_app(test_event_sink=[])
    app.state.session_maker = maker
    accounts = {account["key"]: account["id"] for account in MANIFEST["accounts"]}
    tenants = {tenant["key"]: tenant["id"] for tenant in MANIFEST["tenants"]}
    org = next(row for row in MANIFEST["organizations"] if row["key"] == "primary")
    native = {"iss": ISSUER, "sub": accounts["primary-member"]}
    claims = native

    async def issuer_claims():
        return claims

    app.dependency_overrides[get_access_token_claims] = issuer_claims
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://local") as client:
            path = "/api/v1/authority/organizations"
            params = {"tenant_id": tenants["active"], "limit": 1}
            response = await client.get(path, params=params)
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"] == "no-store"
            assert response.json() == {
                "items": [{"id": org["id"], "tenant_id": tenants["active"], "legal_name": org["legal_name"]}],
                "total": 1, "limit": 1, "offset": 0,
            }
            page = await client.get(path, params={**params, "offset": 1})
            assert page.json() == {"items": [], "total": 1, "limit": 1, "offset": 1}
            assert (await client.get(path, params={**params, "tenant_id": tenants["isolation"]})).status_code == 403
            for rejected in (
                {**native, "sub": accounts["disabled-member"]},
                {**native, "iss": "https://other.invalid"},
                {**native, "spanopticon_auth": "tenant_session"},
                {**native, "nightly_run": {"run": "signed-run"}},
            ):
                claims = rejected
                assert (await client.get(path, params=params)).status_code == 403
            claims = native
            async with maker() as db, db.begin(), scope(db, uuid.UUID(tenants["active"])):
                await db.execute(text("""
                    UPDATE organization_memberships SET enabled=false
                     WHERE organization_id=:organization AND user_id IN (
                        SELECT id FROM users WHERE tenant_id=:tenant AND keycloak_sub=:subject
                     )
                """), {"organization": uuid.UUID(org["id"]), "tenant": uuid.UUID(tenants["active"]),
                       "subject": native["sub"]})
            response = await client.get(path, params=params)
            assert response.json() == {"items": [], "total": 0, "limit": 1, "offset": 0}
    finally:
        await engine.dispose()
