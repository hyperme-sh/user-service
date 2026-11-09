"""Canonical graph bootstrap on isolated PostgreSQL; no live IdP or credentials."""

import hashlib
import json
from pathlib import Path
import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from user_service.fixture_bootstrap import seed, identifier
from user_service.scoped_authority import allowed

DATA = (Path(__file__).parent / "data/canonical-test-fixtures.json").read_bytes()
MANIFEST = json.loads(DATA)
ISSUER = "https://auth.test.hyperme.sh/realms/controlplane"
BINDINGS = json.dumps(
    {
        "issuer": ISSUER,
        "generation": MANIFEST["generation"],
        "subjects": [
            {
                "account_key": a["key"],
                "id": a["id"],
                "email": a["email"],
                "enabled": a["enabled"],
            }
            for a in MANIFEST["accounts"]
        ],
    }
).encode()


def bootstrap(engine, data=DATA, bindings=BINDINGS, **changes):
    args = dict(
        generation=MANIFEST["generation"],
        issuer=ISSUER,
        manifest_sha256=hashlib.sha256(data).hexdigest(),
        source_sha="a" * 40,
    )
    args.update(changes)
    return seed(engine, data, bindings, **args)


async def test_canonical_graph_has_no_implicit_network_admin_tenant_role(
    empty_authority_owner,
):
    owner = empty_authority_owner
    receipt = bootstrap(owner)
    assert (
        receipt["networks"],
        receipt["tenants"],
        receipt["organizations"],
        receipt["identities"],
        receipt["tenant_profiles"],
    ) == (3, 2, 3, 14, 11)
    assert receipt["runtime_accepted"] is False
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenants = {t["key"]: uuid.UUID(t["id"]) for t in MANIFEST["tenants"]}
    orgs = {o["key"]: uuid.UUID(o["id"]) for o in MANIFEST["organizations"]}
    engine = create_async_engine(owner.url.set(drivername="postgresql+asyncpg"))
    maker = async_sessionmaker(engine)
    try:
        async with maker() as db, db.begin():
            for network in MANIFEST["networks"]:
                subject = accounts[network["admin"]]["id"]
                assert await allowed(
                    db, subject=subject, action="network.admin", network=network["id"]
                )
                for other in MANIFEST["networks"]:
                    if other["id"] != network["id"]:
                        assert not await allowed(
                            db,
                            subject=subject,
                            action="network.admin",
                            network=other["id"],
                        )
            assert await allowed(
                db,
                subject=accounts["network-admin"]["id"],
                action="tenant.admin",
                tenant=tenants["active"],
            )
            assert not await allowed(
                db,
                subject=accounts["s3r-network-admin"]["id"],
                action="tenant.admin",
                tenant=tenants["active"],
            )
            assert not await allowed(
                db,
                subject=accounts["network-admin"]["id"],
                action="lease.purchase",
                tenant=tenants["active"],
                organization=orgs["primary"],
            )
            assert await allowed(
                db,
                subject=accounts["primary-payer"]["id"],
                action="lease.purchase",
                tenant=tenants["active"],
                organization=orgs["primary"],
            )
            assert not await allowed(
                db,
                subject=accounts["primary-payer"]["id"],
                action="lease.purchase",
                tenant=tenants["active"],
                organization=orgs["other"],
            )
            for actor in ["primary-member", "disabled-member", "unassociated"]:
                assert not await allowed(
                    db,
                    subject=accounts[actor]["id"],
                    action="lease.purchase",
                    tenant=tenants["active"],
                    organization=orgs["primary"],
                )
            assert not await allowed(
                db,
                subject=accounts["wrongadmin"]["id"],
                action="tenant.admin",
                tenant=tenants["isolation"],
            )
            from user_service.scoped_authority import scope

            async with scope(db, tenants["active"]):
                assert (
                    await db.scalar(
                        text(
                            "SELECT count(*) FROM users WHERE tenant_id=:tenant AND keycloak_sub=:sub"
                        ),
                        {
                            "tenant": tenants["active"],
                            "sub": accounts["network-admin"]["id"],
                        },
                    )
                    == 0
                )
    finally:
        await engine.dispose()


def test_seed_is_fresh_only_and_cannot_repair_existing_roles(empty_authority_owner):
    bootstrap(empty_authority_owner)
    with pytest.raises(ValueError, match="fresh empty"):
        bootstrap(empty_authority_owner)
    with empty_authority_owner.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM authority_fixture_generation")) == 1


@pytest.mark.parametrize("boundary", ["issuer", "subject", "enabled", "inventory"])
def test_wrong_provider_inventory_does_not_create_any_fixtures(
    empty_authority_owner, boundary
):
    bindings = json.loads(BINDINGS)
    if boundary == "issuer":
        bindings["issuer"] = "https://wrong.invalid/realm"
    if boundary == "subject":
        bindings["subjects"][0]["id"] = str(uuid.uuid4())
    if boundary == "enabled":
        bindings["subjects"][0]["enabled"] = False
    if boundary == "inventory":
        bindings["subjects"].pop()
    with pytest.raises(ValueError):
        bootstrap(empty_authority_owner, bindings=json.dumps(bindings).encode())
    with empty_authority_owner.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM tenants")) == 0
        assert db.scalar(text("SELECT count(*) FROM authority_fixture_generation")) == 0


def test_mid_seed_failure_rolls_back_entire_graph(empty_authority_owner):
    data = json.loads(DATA)
    data["organizations"][1]["id"] = data["organizations"][0]["id"]
    data = json.dumps(data).encode()
    with pytest.raises(IntegrityError):
        bootstrap(empty_authority_owner, data=data)
    with empty_authority_owner.connect() as db:
        assert db.scalar(text("SELECT count(*) FROM tenants")) == 0
        assert db.scalar(text("SELECT count(*) FROM users")) == 0
        assert db.scalar(text("SELECT count(*) FROM authority_fixture_generation")) == 0


async def test_scoped_login_and_host_context_are_read_only(
    empty_authority_owner, monkeypatch
):
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from auth_service.schemas import AuthMeResponse
    from user_service.identity_tenant_switch import authorize_tenant_switch
    from user_service.identity_session_member import authorize_session_member
    from user_service.identity_host_setup import (
        authorize_host_setup,
        authorize_host_organization,
    )

    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    primary = uuid.UUID(
        next(o["id"] for o in MANIFEST["organizations"] if o["key"] == "primary")
    )
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    try:
        async with async_sessionmaker(engine)() as db, db.begin():
            for key in [
                "network-admin",
                "s3r-network-admin",
                "primary-admin",
                "host-owner",
                "disabled-member",
                "wrongadmin",
            ]:
                actor = AuthMeResponse(
                    sub=accounts[key]["id"],
                    email=accounts["network-admin"]["email"],
                    roles=["admin"],
                )
                grant = await authorize_tenant_switch(actor, tenant, db)
                if key in ["s3r-network-admin", "disabled-member", "wrongadmin"]:
                    assert grant is None
                else:
                    assert grant.role_name == (
                        "network-admin" if key == "network-admin" else "user"
                    )
                    assert await authorize_session_member(actor.sub, tenant, db)
                host = await authorize_host_setup(actor.sub, tenant, db)
                context = await authorize_host_organization(actor.sub, tenant, db)
                if key == "host-owner":
                    assert (
                        host
                        and context
                        and context.user_id == host.user_id
                        and context.organization_id == primary
                    )
                else:
                    assert host is None and context is None
        with empty_authority_owner.connect() as db:
            assert (
                db.scalar(text("SELECT count(*) FROM users WHERE tenant_id IS NULL"))
                == 14
            )
    finally:
        await engine.dispose()


async def test_unseeded_authority_schema_preserves_legacy_readiness(
    empty_authority_owner, monkeypatch
):
    from user_service.scoped_database import check

    monkeypatch.delenv("USER_SCOPED_AUTHORITY_REQUIRED", raising=False)
    monkeypatch.delenv("USER_TEST_FIXTURE_GENERATION", raising=False)
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    try:
        await check(engine)
    finally:
        await engine.dispose()


async def test_runtime_cannot_modify_bootstrap_authority(
    empty_authority_owner, migrated_sync_url, monkeypatch
):
    owner = empty_authority_owner
    bootstrap(owner)
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from user_service.scoped_database import check

    root = create_engine(migrated_sync_url)
    name = "runtime_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    schema = owner.url.username
    with root.begin() as db:
        db.exec_driver_sql(
            f"CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
        )
        db.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{name}"')
        db.exec_driver_sql(
            f'GRANT SELECT ON ALL TABLES IN SCHEMA "{schema}" TO "{name}"'
        )
        db.exec_driver_sql(f'ALTER ROLE "{name}" SET search_path TO "{schema}",public')
    engine = create_async_engine(
        make_url(migrated_sync_url).set(
            drivername="postgresql+asyncpg", username=name, password=password
        )
    )
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    monkeypatch.setenv("USER_TEST_FIXTURE_GENERATION", MANIFEST["generation"])
    monkeypatch.setenv("USER_TEST_FIXTURE_SHA256", hashlib.sha256(DATA).hexdigest())
    monkeypatch.setenv("GIT_SHA", "a" * 40)
    try:
        await check(engine)
        monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "0")
        with pytest.raises(RuntimeError, match="requires scoped authority"):
            await check(engine)
        monkeypatch.delenv("USER_TEST_FIXTURE_GENERATION")
        for legacy in (None, "0"):
            if legacy is None:
                monkeypatch.delenv("USER_SCOPED_AUTHORITY_REQUIRED", raising=False)
            else:
                monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", legacy)
            with pytest.raises(RuntimeError, match="requires scoped authority"):
                await check(engine)
        monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
        with pytest.raises(RuntimeError, match="requires explicit readiness bindings"):
            await check(engine)
        monkeypatch.setenv("USER_TEST_FIXTURE_GENERATION", MANIFEST["generation"])
        monkeypatch.setenv("USER_TEST_FIXTURE_SHA256", "b" * 64)
        with pytest.raises(RuntimeError, match="not seeded"):
            await check(engine)
        monkeypatch.setenv("USER_TEST_FIXTURE_SHA256", hashlib.sha256(DATA).hexdigest())
        with root.begin() as db:
            db.exec_driver_sql(
                f'GRANT UPDATE(enabled) ON "{schema}".authority_network_admins TO "{name}"'
            )
        with pytest.raises(RuntimeError, match="modify configured authority"):
            await check(engine)
        with root.begin() as db:
            db.exec_driver_sql(
                f'REVOKE UPDATE(enabled) ON "{schema}".authority_network_admins FROM "{name}"'
            )
        await check(engine)
        with root.begin() as db:
            db.exec_driver_sql(f'ALTER TABLE "{schema}".users OWNER TO "{name}"')
        try:
            with pytest.raises(RuntimeError, match="owns an authority RLS table"):
                await check(engine)
        finally:
            with root.begin() as db:
                db.exec_driver_sql(f'ALTER TABLE "{schema}".users OWNER TO "{schema}"')
        privileged = create_async_engine(owner.url.set(drivername="postgresql+asyncpg"))
        try:
            with pytest.raises(RuntimeError, match="migrator"):
                await check(privileged)
        finally:
            await privileged.dispose()
    finally:
        await engine.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP OWNED BY "{name}"')
            db.exec_driver_sql(f'DROP ROLE "{name}"')
        root.dispose()


async def test_enrollment_reads_existing_capabilities_without_granting_roles(
    empty_authority_owner, monkeypatch
):
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from auth_service.schemas import AuthMeResponse
    from user_service.identity_enrollment import grant_held_roles
    from user_service import identity_enrollment
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    organization = uuid.UUID(next(o["id"] for o in MANIFEST["organizations"] if o["key"] == "primary"))
    resolve = AsyncMock(return_value=organization)
    monkeypatch.setattr(identity_enrollment, "host_binding_client", lambda: SimpleNamespace(resolve=resolve))

    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    try:
        async with async_sessionmaker(engine)() as db, db.begin():
            for actor, expected in [
                ("host-owner", ("host", "renter")),
                ("primary-payer", ("renter",)),
                ("unassociated", ()),
            ]:
                result = await grant_held_roles(
                    db,
                    AuthMeResponse(
                        sub=accounts[actor]["id"], roles=["admin", "host", "renter"]
                    ),
                    tenant_id=tenant,
                    requested=["host", "renter", "org_admin"],
                )
                assert result.granted == expected and "org_admin" in result.refused
                assert result.org_admin is None
            assert await db.scalar(text("SELECT count(*) FROM api_keys")) == 0
            resolve.assert_awaited_once_with(tenant, accounts["host-owner"]["id"])
    finally:
        await engine.dispose()


@pytest.mark.parametrize("outcome", ["success", "wrong-organization", "unavailable", "renter-only", "not-host"])
async def test_configured_host_grant_requires_exact_owner_reservation(empty_authority_owner, monkeypatch, outcome):
    """Real configured membership and HTTP client; no live owner or shared writes."""
    import httpx
    from auth_service.host_binding_client import HttpHostBindingClient
    from auth_service.schemas import AuthMeResponse
    from fastapi import HTTPException
    from user_service import identity_enrollment as enrollment

    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active"))
    org = uuid.UUID(next(o["id"] for o in MANIFEST["organizations"] if o["key"] == "primary"))
    actor = "primary-payer" if outcome == "not-host" else "host-owner"
    subject = accounts[actor]["id"]
    calls = []
    def respond(request):
        calls.append(request)
        assert request.url.path == "/api/v1/hypermesh/internal/host-organization"
        assert request.headers["x-tenant-id"] == str(tenant)
        assert request.headers["x-internal-token"] == "isolated-owner-" + "x" * 32
        assert json.loads(request.content) == {"tenant_id": str(tenant), "subject": subject}
        if outcome == "unavailable":
            return httpx.Response(503)
        return httpx.Response(200, json={"tenant_id": str(tenant), "subject": subject,
            "organization_id": str(uuid.uuid4() if outcome == "wrong-organization" else org)})
    client = HttpHostBindingClient("https://owner.invalid", "isolated-owner-" + "x" * 32, httpx.MockTransport(respond))
    monkeypatch.setattr(enrollment, "host_binding_client", lambda: client)
    engine = create_async_engine(empty_authority_owner.url.set(drivername="postgresql+asyncpg"))
    try:
        async with async_sessionmaker(engine)() as db, db.begin():
            async def grant():
                return await enrollment.grant_held_roles(db, AuthMeResponse(sub=subject, roles=["host"]),
                    tenant_id=tenant, requested=["renter"] if outcome == "renter-only" else ["host"])
            if outcome == "wrong-organization":
                with pytest.raises(enrollment.EnrollmentError, match="differs from configured authority"):
                    await grant()
            elif outcome == "unavailable":
                with pytest.raises(HTTPException) as error:
                    await grant()
                assert error.value.status_code == 503
            else:
                for _ in range(2):
                    result = await grant()
                    if outcome == "success":
                        assert result.host.organization_id == org and result.device_enrolled is False
                    else:
                        assert result.host is None and "host" not in result.granted
            assert len(calls) == (2 if outcome == "success" else 0 if outcome in ("renter-only", "not-host") else 1)
            assert await db.scalar(text("SELECT count(*) FROM api_keys")) == 0
    finally:
        await engine.dispose()


async def test_host_org_http_uses_purpose_key_and_current_membership(
    empty_authority_owner, tmp_path, monkeypatch
):
    bootstrap(empty_authority_owner)
    from fastapi import FastAPI
    import httpx
    from user_service.host_authority import router
    from user_service.scoped_authority import scope

    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    key = tmp_path / "purpose"
    key.write_text("a" * 64)
    monkeypatch.setenv("HOST_IDENTITY_OWNER_TOKEN_FILE", str(key))
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)
    app = FastAPI()
    app.state.session_maker = maker
    app.include_router(router, prefix="/api/v1")
    headers = {"Authorization": "Bearer " + "a" * 64, "X-Tenant-ID": str(tenant)}
    body = {
        "version": 1,
        "request_id": str(uuid.uuid4()),
        "tenant_id": str(tenant),
        "subject": accounts["host-owner"]["id"],
    }
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/internal/host-authority/organization",
                headers=headers,
                json=body,
            )
            assert (
                result.status_code == 200
                and result.json()["request_id"] == body["request_id"]
            )
            assert result.headers["cache-control"] == "no-store"
            assert (
                await client.post(
                    "/api/v1/internal/host-authority/organization",
                    headers={**headers, "Authorization": "Bearer wrong"},
                    json=body,
                )
            ).status_code == 401
            assert (
                await client.post(
                    "/api/v1/internal/host-authority/organization",
                    headers=headers,
                    json={**body, "subject": accounts["primary-admin"]["id"]},
                )
            ).status_code == 403
            async with maker() as db, db.begin(), scope(db, tenant):
                await db.execute(
                    text(
                        "UPDATE organization_memberships SET enabled=false WHERE user_id=:id"
                    ),
                    {"id": uuid.UUID(result.json()["user_id"])},
                )
            assert (
                await client.post(
                    "/api/v1/internal/host-authority/organization",
                    headers=headers,
                    json=body,
                )
            ).status_code == 403
    finally:
        await engine.dispose()


async def test_banned_host_is_refused_from_fresh_empty_scope(
    empty_authority_owner, monkeypatch
):
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from user_service.identity_host_setup import (
        authorize_host_setup,
        authorize_host_organization,
    )
    from user_service.scoped_authority import scope

    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    account = next(a for a in MANIFEST["accounts"] if a["key"] == "host-owner")
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)
    try:
        async with maker() as db, db.begin():
            grant = await authorize_host_setup(account["id"], tenant, db)
            assert grant
            async with scope(db, tenant):
                await db.execute(
                    text(
                        "INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,'user',:user,'test','configured-admin',now())"
                    ),
                    {"id": uuid.uuid4(), "tenant": tenant, "user": grant.user_id},
                )
        async with maker() as db, db.begin():
            assert not await db.scalar(
                text("SELECT current_setting('app.current_tenant_id',true)")
            )
            assert await authorize_host_setup(account["id"], tenant, db) is None
            assert await authorize_host_organization(account["id"], tenant, db) is None
            assert not await db.scalar(
                text("SELECT current_setting('app.current_tenant_id',true)")
            )
    finally:
        await engine.dispose()


async def test_portal_controls_follow_current_org_billing_and_host_capabilities(
    empty_authority_owner, monkeypatch
):
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from auth_service.schemas import AuthMeResponse
    from user_service.interfaces.api.routes import actor_portal_controls
    from user_service.scoped_authority import scope

    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)
    try:
        async with maker() as db, db.begin():
            for key, pays, hosts in [
                ("primary-payer", True, False),
                ("host-owner", True, True),
                ("primary-member", False, False),
                ("disabled-member", False, False),
                ("unassociated", False, False),
            ]:
                actor = AuthMeResponse(
                    sub=accounts[key]["id"], roles=["admin"], groups=["host", "renter"]
                )
                controls = await actor_portal_controls(db, tenant, actor)
                assert controls.can_checkout == pays and controls.can_mint_keys == pays
                assert (
                    controls.can_see_leases == pays
                    and controls.can_see_host_status == hosts
                )
            async with scope(db, tenant):
                await db.execute(
                    text(
                        "UPDATE organization_memberships SET can_purchase_leases=false"
                    )
                )
            actor = AuthMeResponse(
                sub=accounts["primary-payer"]["id"], groups=["renter"]
            )
            assert not (await actor_portal_controls(db, tenant, actor)).can_checkout
    finally:
        await engine.dispose()


@pytest.mark.parametrize(
    "key,kind,action",
    [
        ("network-admin", "platform", "tenant.admin"),
        ("primary-admin", "profile", "organization.admin"),
        ("primary-payer", "profile", "lease.purchase"),
        ("primary-payer", "platform", "lease.purchase"),
    ],
)
async def test_stale_actor_cannot_use_scoped_authority_after_user_ban(
    empty_authority_owner, monkeypatch, key, kind, action
):
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from user_service.scoped_authority import scope

    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    org = uuid.UUID(
        next(o["id"] for o in MANIFEST["organizations"] if o["key"] == "primary")
    )
    actor = next(a for a in MANIFEST["accounts"] if a["key"] == key)
    user = (
        uuid.UUID(actor["id"])
        if kind == "platform"
        else identifier(
            MANIFEST["generation"], "member", tenant, uuid.UUID(actor["id"])
        )
    )
    query = dict(
        subject=actor["id"],
        tenant=tenant,
        action=action,
        organization=None if action == "tenant.admin" else org,
    )
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)
    try:
        async with maker() as db, db.begin():
            assert await allowed(db, **query)
            async with scope(db, tenant):
                await db.execute(
                    text(
                        "INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,'user',:user,'test','configured-admin',now())"
                    ),
                    {"id": uuid.uuid4(), "tenant": tenant, "user": user},
                )
        async with maker() as db, db.begin():
            assert not await allowed(db, **query)
    finally:
        await engine.dispose()


async def test_org_list_refuses_disabled_global_identity_with_stale_session(
    empty_authority_owner, monkeypatch
):
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from fastapi import FastAPI
    import httpx
    from auth_service.schemas import AuthMeResponse
    from auth_service.deps import get_current_tenant
    from user_service.deps import get_current_user
    from user_service.interfaces.api.routes import router
    from api.infrastructure.persistence.db_session import get_db_session
    from user_service.scoped_authority import scope

    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    account = next(a for a in MANIFEST["accounts"] if a["key"] == "primary-payer")
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def actor():
        return AuthMeResponse(
            sub=account["id"], tenant_id=tenant, roles=["admin"], groups=["renter"]
        )

    async def context():
        return tenant

    async def database():
        async with maker() as db, db.begin(), scope(db, tenant):
            yield db

    app.dependency_overrides.update(
        {get_current_user: actor, get_current_tenant: context, get_db_session: database}
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {"X-Tenant-ID": str(tenant)}
            result = await client.get("/api/v1/organizations", headers=headers)
            assert result.status_code == 200 and result.json()["total"] == 1
            async with maker() as db, db.begin(), scope(db):
                await db.execute(
                    text(
                        "UPDATE users SET is_active=false WHERE tenant_id IS NULL AND keycloak_sub=:subject"
                    ),
                    {"subject": account["id"]},
                )
            result = await client.get("/api/v1/organizations", headers=headers)
            assert result.status_code == 403
    finally:
        await engine.dispose()


@pytest.mark.parametrize("mixed_path", [False, True])
async def test_readiness_rejects_inherited_table_owner_with_set_false(
    empty_authority_owner, migrated_sync_url, monkeypatch, mixed_path
):
    bootstrap(empty_authority_owner)
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from user_service.scoped_database import check

    root = create_engine(migrated_sync_url)
    schema = empty_authority_owner.url.username
    runtime = "runtime_" + uuid.uuid4().hex
    owner = "table_owner_" + uuid.uuid4().hex
    bridge = "bridge_" + uuid.uuid4().hex
    password = uuid.uuid4().hex
    with root.begin() as db:
        for name in [runtime, owner, bridge]:
            db.exec_driver_sql(
                f'CREATE ROLE "{name}" NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE'
            )
        db.exec_driver_sql(f"ALTER ROLE \"{runtime}\" LOGIN PASSWORD '{password}'")
        db.exec_driver_sql(
            f'GRANT USAGE ON SCHEMA "{schema}" TO "{runtime}","{owner}","{bridge}"'
        )
        db.exec_driver_sql(
            f'GRANT SELECT ON ALL TABLES IN SCHEMA "{schema}" TO "{runtime}"'
        )
        db.exec_driver_sql(
            f'ALTER ROLE "{runtime}" SET search_path TO "{schema}",public'
        )
        db.exec_driver_sql(f'ALTER TABLE "{schema}".users OWNER TO "{owner}"')
        if mixed_path:
            db.exec_driver_sql(
                f'GRANT "{owner}" TO "{bridge}" WITH INHERIT TRUE, SET FALSE'
            )
            db.exec_driver_sql(
                f'GRANT "{bridge}" TO "{runtime}" WITH INHERIT FALSE, SET TRUE'
            )
        else:
            db.exec_driver_sql(
                f'GRANT "{owner}" TO "{runtime}" WITH INHERIT TRUE, SET FALSE'
            )
    engine = create_async_engine(
        make_url(migrated_sync_url).set(
            drivername="postgresql+asyncpg", username=runtime, password=password
        )
    )
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    try:
        with pytest.raises(RuntimeError, match="owns an authority RLS table"):
            await check(engine)
    finally:
        await engine.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'ALTER TABLE "{schema}".users OWNER TO "{schema}"')
            for name in [runtime, bridge, owner]:
                db.exec_driver_sql(f'DROP OWNED BY "{name}"')
                db.exec_driver_sql(f'DROP ROLE "{name}"')
        root.dispose()


async def test_billing_context_and_operator_use_current_owner_graph(
    empty_authority_owner, monkeypatch
):
    from controlplane_api.config import settings

    monkeypatch.setattr(
        settings,
        "api_key_exchange_jwt_secret",
        "canonical-operator-isolated-test-secret-not-a-live-key",
    )
    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    from fastapi import FastAPI
    import httpx
    from auth_service.schemas import AuthMeResponse
    from user_service.deps import get_current_user
    from api.infrastructure.persistence.db_session import get_db_session
    from user_service.authority_routes import router
    from user_service.scoped_authority import scope
    from user_service.interfaces.api import operator_routes
    from starlette.requests import Request
    from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt

    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenant = uuid.UUID(
        next(t["id"] for t in MANIFEST["tenants"] if t["key"] == "active")
    )
    orgs = {o["key"]: o["id"] for o in MANIFEST["organizations"]}
    actor = "primary-payer"
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg")
    )
    maker = async_sessionmaker(engine)

    async def user():
        return AuthMeResponse(
            sub=accounts[actor]["id"],
            tenant_id=tenant,
            roles=["admin"],
            groups=["renter"],
        )

    async def database():
        async with maker() as db, db.begin():
            yield db

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides.update({get_current_user: user, get_db_session: database})
    from auth_service.deps import get_access_token_claims

    async def issuer_claims():
        return {"sub": accounts[actor]["id"]}

    app.dependency_overrides[get_access_token_claims] = issuer_claims
    headers = {"X-Tenant-ID": str(tenant)}
    body = {"version": 1, "request_id": str(uuid.uuid4()), "tenant_id": str(tenant)}
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/api/v1/authority/billing-context", headers=headers, json=body
            )
            assert (
                result.status_code == 200
                and result.json()["user_id"] == accounts[actor]["id"]
            )
            assert result.json()["organization_id"] == orgs["primary"]
            assert result.headers["cache-control"] == "no-store"
            assert (
                await client.post(
                    "/api/v1/authority/billing-context",
                    headers=headers,
                    json={**body, "organization_id": orgs["other"]},
                )
            ).status_code == 403
            for actor in [
                "network-admin",
                "primary-member",
                "unassociated",
                "disabled-member",
                "wrongadmin",
            ]:
                assert (
                    await client.post(
                        "/api/v1/authority/billing-context", headers=headers, json=body
                    )
                ).status_code == 403
            actor = "primary-payer"
            async with maker() as db, db.begin(), scope(db, tenant):
                await db.execute(
                    text(
                        "UPDATE organization_memberships SET enabled=false WHERE user_id=:id"
                    ),
                    {
                        "id": identifier(
                            MANIFEST["generation"],
                            "member",
                            tenant,
                            uuid.UUID(accounts[actor]["id"]),
                        )
                    },
                )
            assert (
                await client.post(
                    "/api/v1/authority/billing-context", headers=headers, json=body
                )
            ).status_code == 403
            identity = await client.post(
                "/api/v1/authority/identity-context", headers=headers, json=body
            )
            assert (
                identity.status_code == 200
                and identity.json()["user_id"] == accounts[actor]["id"]
            )
            async with maker() as db, db.begin(), scope(db):
                await db.execute(
                    text(
                        "UPDATE users SET is_active=false WHERE tenant_id IS NULL AND keycloak_sub=:subject"
                    ),
                    {"subject": accounts[actor]["id"]},
                )
            assert (
                await client.post(
                    "/api/v1/authority/identity-context", headers=headers, json=body
                )
            ).status_code == 403
            actor = "other-payer"
            result = await client.post(
                "/api/v1/authority/billing-context", headers=headers, json=body
            )
            assert (
                result.status_code == 200
                and result.json()["organization_id"] == orgs["other"]
            )
        async with maker() as db, db.begin():
            monkeypatch.setattr(operator_routes, "_db", lambda: db)

            def request(key):
                token = mint_tenant_session_jwt(
                    claims={"sub": accounts[key]["id"]},
                    tenant_id=tenant,
                    extra_permissions=["operator:console", "operator:support"],
                )
                return Request(
                    {
                        "type": "http",
                        "method": "GET",
                        "path": "/operator/session",
                        "headers": [
                            (b"authorization", ("Bearer " + token).encode()),
                            (b"x-tenant-id", str(tenant).encode()),
                        ],
                    }
                )

            result = await operator_routes.current_operator(
                request("network-admin"), operator_routes.require_support
            )
            assert "operator:support" in result["permissions"]
            for key in [
                "primary-admin",
                "other-admin",
                "s3r-network-admin",
                "wrongadmin",
            ]:
                with pytest.raises(__import__("fastapi").HTTPException) as refusal:
                    await operator_routes.current_operator(
                        request(key), operator_routes.require_support
                    )
                assert refusal.value.status_code == 403
            async with scope(db, network="hyperme.sh"):
                await db.execute(
                    text("UPDATE authority_network_admins SET enabled=false")
                )
            with pytest.raises(__import__("fastapi").HTTPException):
                await operator_routes.current_operator(
                    request("network-admin"), operator_routes.require_support
                )
            from user_service import account_closure
            from user_service.closure_contracts import OperatorClosureConfirmation

            monkeypatch.setenv("ACCOUNT_CLOSURE_REQUESTS_ENABLED", "true")
            confirmation = OperatorClosureConfirmation(
                confirmation="CLOSE MY ACCOUNT", subject=accounts["primary-payer"]["id"]
            )
            for operation in [
                account_closure.request_operator_closure(
                    request("network-admin"), confirmation, session=db
                ),
                account_closure.operator_closure_status(
                    request("network-admin"),
                    subject=accounts["primary-payer"]["id"],
                    session=db,
                ),
            ]:
                with pytest.raises(__import__("fastapi").HTTPException) as refusal:
                    await operation
                assert refusal.value.status_code == 403
            async with scope(db, tenant):
                assert (
                    await db.scalar(
                        text("SELECT count(*) FROM account_closure_requests")
                    )
                    == 0
                )
    finally:
        await engine.dispose()


async def test_auth_scope_adapter_uses_only_canonical_graph(
    empty_authority_owner, monkeypatch
):
    import asyncio
    import httpx
    from fastapi import FastAPI
    from user_service.scope_adapter import router, check_configuration
    from user_service.scoped_authority import scope

    bootstrap(empty_authority_owner)
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    monkeypatch.setenv("USER_TEST_FIXTURE_GENERATION", MANIFEST["generation"])
    monkeypatch.setenv("USER_SCOPE_GENERATION", MANIFEST["generation"])
    for name in ("AUTH", "PAYMENT", "PLANE"):
        monkeypatch.setenv(name + "_SCOPE_AUTHORITY_TOKEN", "isolated-" + name)
    check_configuration()
    engine = create_async_engine(
        empty_authority_owner.url.set(drivername="postgresql+asyncpg"),
        pool_size=1,
        max_overflow=0,
        pool_timeout=1,
    )
    maker = async_sessionmaker(engine)
    app = FastAPI()
    app.state.session_maker = maker
    app.include_router(router, prefix="/api/v1")
    accounts = {a["key"]: a for a in MANIFEST["accounts"]}
    tenants = {t["key"]: t["id"] for t in MANIFEST["tenants"]}
    orgs = {o["key"]: o["id"] for o in MANIFEST["organizations"]}
    path = "/api/v1/internal/organization-authority/check"
    body = dict(
        subject=accounts["host-owner"]["id"],
        tenant_id=tenants["active"],
        organization_id=orgs["primary"],
        capability="member",
    )
    headers = {"Authorization": "Bearer isolated-AUTH"}
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://local"
        ) as client:
            for actor, org, tenant, allowed in [
                ("host-owner", "primary", "active", True),
                ("primary-admin", "primary", "active", True),
                ("other-admin", "other", "active", True),
                ("other-admin", "primary", "active", False),
                ("primary-payer", "other", "active", False),
                ("disabled-member", "primary", "active", False),
                ("unassociated", "primary", "active", False),
                ("wrongadmin", "primary", "active", False),
                ("wrongadmin", "isolated", "isolation", False),
                ("isolated-member", "isolated", "isolation", False),
                ("network-admin", "primary", "active", False),
                ("host-owner", "primary", "isolation", False),
            ]:
                result = await client.post(
                    path,
                    headers=headers,
                    json={
                        **body,
                        "subject": accounts[actor]["id"],
                        "organization_id": orgs[org],
                        "tenant_id": tenants[tenant],
                    },
                )
                assert result.status_code == 200, result.text
                assert (result.json() is not None) == allowed
                if allowed:
                    assert result.json()["user_id"] == accounts[actor]["id"]
                    assert result.json()["generation"] == MANIFEST["generation"]
                    assert (
                        result.json()["manifest_sha256"]
                        == hashlib.sha256(DATA).hexdigest()
                    )
                    assert result.headers["cache-control"] == "no-store"
            replies = await asyncio.gather(
                *(client.post(path, headers=headers, json=body) for _ in range(4))
            )
            assert all(r.status_code == 200 and r.json() for r in replies)
            assert (
                await client.post(
                    path, headers={"Authorization": "Bearer wrong"}, json=body
                )
            ).status_code == 401
            assert (
                await client.post(
                    path,
                    headers={"Authorization": "Bearer isolated-PAYMENT"},
                    json={**body, "capability": "manage-members"},
                )
            ).status_code == 403
            assert (
                await client.post(
                    path, headers=headers, json={**body, "capability": "purchase"}
                )
            ).status_code == 403
            async with maker() as db, db.begin(), scope(
                db, uuid.UUID(tenants["active"])
            ):
                await db.execute(
                    text(
                        "UPDATE organization_memberships SET enabled=false WHERE user_id IN (SELECT id FROM users WHERE keycloak_sub=:subject)"
                    ),
                    {"subject": body["subject"]},
                )
            result = await client.post(path, headers=headers, json=body)
            assert result.status_code == 200 and result.json() is None
    finally:
        await engine.dispose()


def test_auth_selection_requires_single_canonical_generation(monkeypatch):
    from user_service.scope_adapter import check_configuration

    monkeypatch.setenv("USER_SCOPE_GENERATION", "test-reset-v1")
    monkeypatch.delenv("USER_SCOPED_AUTHORITY_REQUIRED", raising=False)
    with pytest.raises(RuntimeError, match="canonical authority"):
        check_configuration()
    monkeypatch.setenv("USER_SCOPED_AUTHORITY_REQUIRED", "1")
    monkeypatch.setenv("USER_TEST_FIXTURE_GENERATION", "different")
    with pytest.raises(RuntimeError, match="canonical authority"):
        check_configuration()
    monkeypatch.setenv("USER_TEST_FIXTURE_GENERATION", "test-reset-v1")
    check_configuration()


def test_successor_requires_exact_seed_and_packaged_contract(monkeypatch):
    from importlib.resources import files
    from user_service.scoped_database import matches_seed

    row = ("fixture", "a" * 64, "b" * 40, "c" * 64)
    source = "d" * 40
    assert not matches_seed(row, row[0], row[1], source)
    receipt = dict(generation=row[0], manifest_sha256=row[1], seed_source=row[2],
                   subjects_sha256=row[3], runtime_source=source, contract_sha256={
                       name: hashlib.sha256(files("user_service").joinpath(name).read_bytes()).hexdigest()
                       for name in ("fixture_bootstrap.py", "authority_schema.sql")})
    monkeypatch.setenv("USER_TEST_SEED_COMPATIBILITY", json.dumps(receipt))
    assert matches_seed(row, row[0], row[1], source)
    for field in receipt:
        monkeypatch.setenv("USER_TEST_SEED_COMPATIBILITY", json.dumps({**receipt, field: "incorrect"}))
        assert not matches_seed(row, row[0], row[1], source)


def test_product_tenant_adoption_is_atomic_and_repeatable(empty_authority_owner):
    from user_service.adopt_test_tenant import _install
    from user_service.fixture_bootstrap import S3RCH_TEST_TENANT

    engine = empty_authority_owner
    baseline = bootstrap(engine)["manifest_sha256"]
    candidate = json.dumps({**MANIFEST, "tenants": [*MANIFEST["tenants"], S3RCH_TEST_TENANT]}).encode()
    digest = hashlib.sha256(candidate).hexdigest()
    tenant = uuid.UUID(S3RCH_TEST_TENANT["id"])
    for _ in range(2):
        with engine.begin() as db:
            _install(db, MANIFEST["generation"], baseline, digest, tenant)
            assert db.scalar(text("SELECT count(*) FROM roles WHERE tenant_id=:id"), {"id": tenant}) == 3
            assert db.scalar(text("SELECT count(*) FROM users WHERE tenant_id=:id"), {"id": tenant}) == 0
    with pytest.raises(ValueError, match="Installed generation differs"), engine.begin() as db:
        _install(db, MANIFEST["generation"], baseline, "0" * 64, tenant)


@pytest.mark.parametrize("recreation", [1, 2])
def test_recreated_owner_oauth_grants(empty_authority_owner, recreation):
    manifest = json.loads(DATA)
    from user_service.fixture_bootstrap import S3RCH_TEST_TENANT
    manifest["tenants"].append(S3RCH_TEST_TENANT)
    manifest["organizations"].append({"key": "s3rch-primary", "id": str(identifier("test","s3rch-org")), "tenant":"s3rch"})
    manifest["main_organizations"] = {"active": "primary", "isolation": "isolated", "s3rch":"s3rch-primary"}
    manifest["oauth_accounts"] = [
        {"key": key, "id": str(identifier("test", key)), "email": key+"@example.invalid",
         "tenant_role": role, "main_organization_role": org_role}
        for key, role, org_role in [("microsoft","admin","admin"), ("github","member",None), ("google","member","member")]
    ]
    data = json.dumps(manifest).encode()
    bindings = json.loads(BINDINGS)
    bindings["manifest_sha256"] = hashlib.sha256(data).hexdigest()
    bindings["oauth_subjects"] = [
        {"account_key": a["key"], "id": a["id"], "email": a["email"], "enabled": True}
        for a in manifest["oauth_accounts"]
    ]
    bootstrap(empty_authority_owner, data, json.dumps(bindings).encode())
    orgs = {o["key"]: o["id"] for o in manifest["organizations"]}
    with empty_authority_owner.begin() as db:
        for tenant in manifest["tenants"]:
            db.execute(text("SELECT set_config('app.current_tenant_id',:tid,true)"), {"tid":tenant["id"]})
            for account in manifest["oauth_accounts"]:
                row = db.execute(text("""
                    SELECT r.name, m.role, m.organization_id
                    FROM users u JOIN roles r ON r.id=u.role_id
                    LEFT JOIN organization_memberships m ON m.user_id=u.id AND m.tenant_id=u.tenant_id
                    WHERE u.tenant_id=:tid AND u.keycloak_sub=:sub
                """), {"tid":tenant["id"], "sub":account["id"]}).one()
                assert row.name == ("admin" if account["tenant_role"] == "admin" else "user")
                assert row.role == account["main_organization_role"]
                if row.role:
                    assert str(row.organization_id) == orgs[manifest["main_organizations"][tenant["key"]]]
                else:
                    assert row.organization_id is None
