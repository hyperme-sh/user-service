from pathlib import Path

"""Real PostgreSQL authority scopes under a nonprivileged FORCE-RLS owner."""
from importlib.resources import files
from types import SimpleNamespace
import uuid
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.exc import IntegrityError
from controlplane_events.owner_schema import migrate
from user_service.authority_migrate import install
from user_service.scoped_authority import allowed, scope


@pytest.fixture
async def authority(migrated_sync_url):
    name = "authority_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    root = create_engine(migrated_sync_url)
    with root.begin() as db:
        db.exec_driver_sql(
            f"CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
        )
        db.exec_driver_sql(f'CREATE SCHEMA "{name}" AUTHORIZATION "{name}"')
        db.exec_driver_sql(f'ALTER ROLE "{name}" SET search_path TO "{name}",public')
    url = make_url(migrated_sync_url).set(username=name, password=password)
    sync = create_engine(url)
    migrate(
        sync,
        revision="0001_owner_schema",
        ddl=Path(__file__).parent.joinpath("fixtures/owner-schema.sql").read_text(),
    )
    install(sync)
    install(sync)
    engine = create_async_engine(url.set(drivername="postgresql+asyncpg"))
    maker = async_sessionmaker(engine, expire_on_commit=False)
    s = SimpleNamespace(
        tenant=uuid.uuid4(),
        isolated=uuid.uuid4(),
        org=uuid.uuid4(),
        other=uuid.uuid4(),
        wrongorg=uuid.uuid4(),
        users={},
        identities={},
    )
    async with maker() as db, db.begin():
        for tenant, active in [(s.tenant, True), (s.isolated, False)]:
            await db.execute(
                text(
                    "INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,:active)"
                ),
                {"id": tenant, "name": str(tenant), "active": active},
            )
        for network, actor in [
            ("hyperme.sh", "network-admin"),
            ("s3r.ch", "other-network-admin"),
        ]:
            async with scope(db, network=network):
                await db.execute(
                    text("INSERT INTO authority_networks(id) VALUES(:network)"),
                    {"network": network},
                )
                uid = uuid.uuid4()
                s.users[actor] = uid
                s.identities[actor] = uid
                await db.execute(
                    text(
                        "INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,NULL,:sub,:email,'Test','Admin','unspecified',true)"
                    ),
                    {"id": uid, "sub": actor, "email": actor + "@example.invalid"},
                )
                await db.execute(
                    text(
                        "INSERT INTO authority_network_admins(network_id,user_id) VALUES(:network,:user)"
                    ),
                    {"network": network, "user": uid},
                )
        for tenant in [s.tenant, s.isolated]:
            async with scope(db, tenant):
                await db.execute(
                    text("INSERT INTO authority_tenants VALUES(:tenant,'hyperme.sh')"),
                    {"tenant": tenant},
                )
        for tenant, org in [
            (s.tenant, s.org),
            (s.tenant, s.other),
            (s.isolated, s.wrongorg),
        ]:
            async with scope(db, tenant):
                await db.execute(
                    text(
                        "INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:id,:tenant,:name)"
                    ),
                    {"id": org, "tenant": tenant, "name": str(org)},
                )
        for actor, tenant, org, role, pays, enabled in [
            ("org-admin", s.tenant, s.org, "admin", True, True),
            ("other-org-admin", s.tenant, s.other, "admin", True, True),
            ("payer", s.tenant, s.org, "member", True, True),
            ("member", s.tenant, s.org, "member", False, True),
            ("disabled", s.tenant, s.org, "member", False, False),
            ("wrongadmin", s.isolated, s.wrongorg, "admin", False, True),
        ]:
            async with scope(db):
                gid = uuid.uuid4()
                s.identities[actor] = gid
                await db.execute(
                    text(
                        "INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,NULL,:sub,:email,'Test','Identity','unspecified',:active)"
                    ),
                    {
                        "id": gid,
                        "sub": actor,
                        "email": actor + "@example.invalid",
                        "active": enabled,
                    },
                )
            async with scope(db, tenant):
                uid = uuid.uuid4()
                s.users[actor] = uid
                await db.execute(
                    text(
                        "INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,:tenant,:sub,:email,'Test','Member','unspecified',:active)"
                    ),
                    {
                        "id": uid,
                        "tenant": tenant,
                        "sub": actor,
                        "email": actor + "@example.invalid",
                        "active": enabled,
                    },
                )
                await db.execute(
                    text(
                        "INSERT INTO organization_memberships VALUES(:tenant,:org,:user,:role,:pays,true)"
                    ),
                    {
                        "tenant": tenant,
                        "org": org,
                        "user": uid,
                        "role": role,
                        "pays": pays,
                    },
                )
                if actor == "wrongadmin":
                    rid = uuid.uuid4()
                    await db.execute(
                        text(
                            "INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,'admin','[]'::jsonb)"
                        ),
                        {"id": rid, "tenant": tenant},
                    )
                    await db.execute(
                        text("UPDATE users SET role_id=:role WHERE id=:user"),
                        {"role": rid, "user": uid},
                    )
    s.maker, s.engine, s.sync = maker, engine, sync
    try:
        yield s
    finally:
        await engine.dispose()
        sync.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP SCHEMA "{name}" CASCADE')
            db.exec_driver_sql(f'DROP ROLE "{name}"')
        root.dispose()


async def check(s, subject, action, **scope_values):
    async with s.maker() as db, db.begin():
        return await allowed(db, subject=subject, action=action, **scope_values)


async def test_network_admin_is_not_cross_network_or_billing_authority(authority):
    s = authority
    assert await check(s, "network-admin", "network.admin", network="hyperme.sh")
    assert not await check(s, "network-admin", "network.admin", network="s3r.ch")
    assert not await check(s, "other-network-admin", "tenant.admin", tenant=s.tenant)
    assert await check(s, "network-admin", "tenant.admin", tenant=s.tenant)
    assert not await check(
        s, "network-admin", "lease.purchase", tenant=s.tenant, organization=s.org
    )


async def test_org_admin_is_only_own_org(authority):
    s = authority
    assert await check(
        s, "org-admin", "organization.admin", tenant=s.tenant, organization=s.org
    )
    assert not await check(
        s, "org-admin", "organization.admin", tenant=s.tenant, organization=s.other
    )
    assert not await check(s, "org-admin", "tenant.admin", tenant=s.tenant)
    assert not await check(s, "org-admin", "network.admin", network="hyperme.sh")
    assert not await check(s, "org-admin", "approval.resolve", tenant=s.tenant)


async def test_paying_nonbilling_disabled_and_unassociated_members(authority):
    s = authority
    assert await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
    for actor in ["member", "disabled", "unassociated"]:
        assert not await check(
            s, actor, "lease.purchase", tenant=s.tenant, organization=s.org
        )
    assert not await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.other
    )
    assert not await check(
        s, "payer", "organization.admin", tenant=s.tenant, organization=s.org
    )


async def test_wrongadmin_retains_local_grant_but_inactive_tenant_refuses(authority):
    s = authority
    async with s.maker() as db, db.begin(), scope(db, s.isolated):
        assert await db.scalar(
            text(
                "SELECT role='admin' FROM organization_memberships WHERE user_id=:user"
            ),
            {"user": s.users["wrongadmin"]},
        )
    assert not await check(
        s,
        "wrongadmin",
        "organization.admin",
        tenant=s.isolated,
        organization=s.wrongorg,
    )
    assert not await check(
        s, "wrongadmin", "organization.admin", tenant=s.tenant, organization=s.org
    )


async def test_current_membership_revocation_and_profile_deactivation(authority):
    s = authority
    assert await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
    async with s.maker() as db, db.begin(), scope(db, s.tenant):
        await db.execute(
            text("UPDATE organization_memberships SET enabled=false WHERE user_id=:id"),
            {"id": s.users["payer"]},
        )
        await db.execute(
            text("UPDATE users SET is_active=false WHERE id=:id"),
            {"id": s.users["org-admin"]},
        )
    assert not await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
    assert not await check(
        s, "org-admin", "organization.admin", tenant=s.tenant, organization=s.org
    )


async def test_database_rejects_cross_tenant_membership(authority):
    s = authority
    with pytest.raises(IntegrityError):
        async with s.maker() as db, db.begin(), scope(db, s.tenant):
            await db.execute(
                text(
                    "INSERT INTO organization_memberships VALUES(:tenant,:org,:user,'admin',true,true)"
                ),
                {"tenant": s.tenant, "org": s.wrongorg, "user": s.users["payer"]},
            )


@pytest.fixture
async def authority_http(authority, monkeypatch):
    from fastapi import FastAPI
    import httpx
    from api.core import config
    from api.infrastructure.persistence.db_session import get_db_session
    from user_service.authority_routes import router

    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    monkeypatch.setattr(
        config.settings,
        "api_key_exchange_jwt_secret",
        "fixture-scope-secret-at-least-thirty-two-bytes",
    )
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def session():
        async with authority.maker() as db, db.begin():
            yield db

    app.dependency_overrides[get_db_session] = session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://owner.test"
    ) as client:
        yield client


def headers(s, actor, tenant=None):
    from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt

    tid = tenant or s.tenant
    token = mint_tenant_session_jwt(
        claims={
            "sub": actor,
            "email": actor + "@example.invalid",
            "azp": "controlplane-frontend",
            "amr": ["pwd"],
            "realm_access": {"roles": ["admin"]},
            "permissions": ["*"],
        },
        tenant_id=tid,
    )
    return {"Authorization": "Bearer " + token, "X-Tenant-ID": str(tid)}


async def test_http_current_subject_scope_and_tenant_binding(authority, authority_http):
    s = authority
    c = authority_http
    body = dict(
        version=1,
        request_id=str(uuid.uuid4()),
        action="organization.admin",
        tenant_id=str(s.tenant),
        organization_id=str(s.org),
    )
    reply = await c.post(
        "/api/v1/authority/check", headers=headers(s, "org-admin"), json=body
    )
    assert reply.status_code == 200, reply.text
    assert reply.json()["allowed"] is True and reply.json()["subject"] == "org-admin"
    assert reply.headers["cache-control"] == "no-store"
    denied = await c.post(
        "/api/v1/authority/check", headers=headers(s, "other-org-admin"), json=body
    )
    assert denied.status_code == 200 and denied.json()["allowed"] is False
    mismatch = await c.post(
        "/api/v1/authority/check",
        headers=headers(s, "org-admin", s.isolated),
        json=body,
    )
    assert mismatch.status_code == 403
    forged = await c.post(
        "/api/v1/authority/check",
        headers=headers(s, "member"),
        json={**body, "subject": "network-admin"},
    )
    assert forged.status_code == 422


async def test_http_org_member_crud_does_not_grant_tenant_or_network_authority(
    authority, authority_http
):
    s = authority
    c = authority_http
    path = f'/api/v1/organizations/{s.org}/members/{s.users["payer"]}'
    body = dict(user_id=str(s.users["payer"]), role="member", can_purchase_leases=False)
    refused = await c.put(path, headers=headers(s, "other-org-admin"), json=body)
    assert refused.status_code == 403
    assert await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
    changed = await c.put(path, headers=headers(s, "org-admin"), json=body)
    assert changed.status_code == 200, changed.text
    assert not await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
    bad = await c.put(
        path, headers=headers(s, "org-admin"), json={**body, "role": "network-admin"}
    )
    assert bad.status_code == 422
    assert (await c.delete(path, headers=headers(s, "org-admin"))).status_code == 204
    assert not await check(
        s, "payer", "organization.read", tenant=s.tenant, organization=s.org
    )
    assert await check(
        s, "other-org-admin", "lease.purchase", tenant=s.tenant, organization=s.other
    )


async def test_wrongadmin_own_scope_positive_in_disposable_active_variant(authority):
    # This changes only the isolated local PostgreSQL fixture, never shared TEST.
    s = authority
    async with s.maker() as db, db.begin():
        await db.execute(
            text("UPDATE tenants SET is_active=true WHERE id=:id"), {"id": s.isolated}
        )
    assert await check(s, "wrongadmin", "tenant.admin", tenant=s.isolated)
    assert await check(
        s,
        "wrongadmin",
        "organization.admin",
        tenant=s.isolated,
        organization=s.wrongorg,
    )
    assert not await check(
        s, "wrongadmin", "organization.admin", tenant=s.tenant, organization=s.org
    )
    assert not await check(s, "wrongadmin", "network.admin", network="hyperme.sh")


async def test_disabled_network_does_not_leave_local_admin_authority(authority):
    s = authority
    async with s.maker() as db, db.begin(), scope(db, network="hyperme.sh"):
        await db.execute(
            text("UPDATE authority_networks SET enabled=false WHERE id='hyperme.sh'")
        )
    assert not await check(s, "network-admin", "tenant.admin", tenant=s.tenant)
    assert not await check(
        s, "org-admin", "organization.admin", tenant=s.tenant, organization=s.org
    )


async def test_global_identity_disable_refuses_still_active_org_membership(authority):
    s = authority
    assert await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
    async with s.maker() as db, db.begin(), scope(db):
        await db.execute(
            text("UPDATE users SET is_active=false WHERE id=:id"),
            {"id": s.identities["payer"]},
        )
    assert not await check(
        s, "payer", "lease.purchase", tenant=s.tenant, organization=s.org
    )
