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
    finally:
        await engine.dispose()
