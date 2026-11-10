"""Self identity is a persisted tenant binding, independent of role/email/UUID."""

import uuid

import pytest

from auth_service.deps import get_access_token_claims
from test_user_mutation_authority import authority, revoke  # noqa: F401


@pytest.fixture(autouse=True)
def claims(app):
    async def verified_claims():
        return {}

    app.dependency_overrides[get_access_token_claims] = verified_claims


async def test_member_reads_existing_profile_without_mutation(http_client, authority):
    s = authority
    s.execute("UPDATE users SET role_id=NULL WHERE id=:id", id=s.actor)
    before = s.snapshot()
    result = await http_client.get("/api/v1/me/profile", headers=s.headers)
    assert result.status_code == 200, result.text
    assert result.json()["id"] == str(s.actor)
    assert result.json()["tenant_id"] == str(s.tenant)
    assert result.json()["email"] == s.email
    assert result.headers["cache-control"] == "no-store"
    assert str(s.actor) != s.subject
    assert s.snapshot() == before


@pytest.mark.parametrize("reason", [
    "inactive", "deleted", "removed", "unbound", "foreign_subject", "local_id_subject",
])
async def test_unavailable_profile_never_falls_back_to_email_or_id(http_client, authority, reason):
    s = authority
    revoke(s, reason)
    before = s.snapshot()
    result = await http_client.get("/api/v1/me/profile", headers=s.headers)
    assert result.status_code == 404, result.text
    assert s.snapshot() == before


async def test_inactive_tenant_is_denied(http_client, authority):
    revoke(authority, "tenant_inactive")
    result = await http_client.get("/api/v1/me/profile", headers=authority.headers)
    assert result.status_code == 403, result.text


@pytest.mark.parametrize("header,status", [(None, 400), ("invalid", 400), (str(uuid.uuid4()), 403)])
async def test_profile_requires_matching_tenant_header(http_client, authority, header, status):
    headers = dict(authority.headers)
    if header is None:
        del headers["X-Tenant-ID"]
    else:
        headers["X-Tenant-ID"] = header
    result = await http_client.get("/api/v1/me/profile", headers=headers)
    assert result.status_code == status, result.text


async def test_scoped_profile_rechecks_identity_bans_and_selection(empty_authority_owner, monkeypatch):
    import hashlib
    import httpx
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from auth_service.deps import get_current_tenant, get_current_user
    from auth_service.schemas import AuthMeResponse
    from test_fixture_bootstrap import bootstrap, DATA, MANIFEST
    from user_service.app import create_app
    from user_service.scoped_authority import scope

    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    engine = create_async_engine(empty_authority_owner.url.set(drivername="postgresql+asyncpg"))
    maker = async_sessionmaker(engine)
    own_app = create_app(test_event_sink=[])
    own_app.state.session_maker = maker
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active"))
    actor = "primary-payer"
    token_claims = {
        "scope_version": 1, "tenant_id": str(tenant), "network_id": "hyperme.sh",
        "spanopticon_auth": "tenant_session", "scope_kind": "network",
        "scope_generation": MANIFEST["generation"],
        "scope_manifest_sha256": hashlib.sha256(DATA).hexdigest(),
    }

    async def current_user():
        return AuthMeResponse(sub=accounts[actor]["id"], tenant_id=tenant)

    async def current_tenant():
        return tenant

    async def current_claims():
        return {**token_claims, "sub": accounts[actor]["id"]}

    own_app.dependency_overrides[get_current_user] = current_user
    own_app.dependency_overrides[get_current_tenant] = current_tenant
    own_app.dependency_overrides[get_access_token_claims] = current_claims
    headers = {"X-Tenant-ID": str(tenant), "Authorization": "Bearer isolated-test"}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(own_app), base_url="http://local") as client:
            ok = await client.get("/api/v1/me/profile", headers=headers)
            assert ok.status_code == 200, ok.text
            profile_id = uuid.UUID(ok.json()["id"])
            assert ok.headers["cache-control"] == "no-store"
            token_claims["scope_manifest_sha256"] = "0" * 64
            stale = await client.get("/api/v1/me/profile", headers=headers)
            assert stale.status_code == 403, stale.text
            token_claims["scope_manifest_sha256"] = hashlib.sha256(DATA).hexdigest()
            async with maker() as session, session.begin(), scope(session, tenant):
                await session.execute(text("UPDATE users SET is_active=false WHERE id=:id AND tenant_id=:tenant"), {"id": profile_id, "tenant": tenant})
            inactive = await client.get("/api/v1/me/profile", headers=headers)
            assert inactive.status_code == 404, inactive.text
            actor = "disabled-member"
            disabled = await client.get("/api/v1/me/profile", headers=headers)
            assert disabled.status_code == 403, disabled.text
            actor = "network-admin"
            unbound = await client.get("/api/v1/me/profile", headers=headers)
            assert unbound.status_code == 404, unbound.text
    finally:
        await engine.dispose()
