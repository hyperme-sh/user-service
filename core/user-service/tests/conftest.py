from __future__ import annotations
from pathlib import Path

import historical_db_fixture  # noqa: F401; verified private historical migrations

import os
import uuid
from collections import namedtuple
from typing import Any

import pytest
from sqlalchemy import create_engine, text

from api.core import config as api_config
from api.infrastructure.security import keycloak_jwt as kc_jwt
from auth_service.deps import get_current_tenant, get_current_user
from auth_service.schemas import AuthMeResponse
from spanopticon_tests.fixtures.postgres import (
    normalize_sync_sqlalchemy_url,
)
from testcontainers.community.postgres import PostgresContainer

Seed = namedtuple("Seed", ["ta", "tb", "ra", "rb"])


@pytest.fixture(autouse=True)
def _clear_keycloak_validator_cache() -> None:
    kc_jwt._validator_singleton.cache_clear()
    yield
    kc_jwt._validator_singleton.cache_clear()


@pytest.fixture(scope="session")
def require_docker() -> None:
    if os.environ.get("SKIP_TESTCONTAINERS", "").lower() in ("1", "true", "yes"):
        pytest.skip("SKIP_TESTCONTAINERS is set")
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker not available for testcontainers: {exc}")


@pytest.fixture(scope="session")
def postgres_container(require_docker: None):
    with PostgresContainer("postgres:16-alpine@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416") as pg:
        yield pg


@pytest.fixture(scope="session")
def postgres_sync_url(postgres_container: PostgresContainer) -> str:
    return normalize_sync_sqlalchemy_url(postgres_container.get_connection_url())


@pytest.fixture(scope="session")
def migrated_sync_url(postgres_sync_url: str) -> str:
    from controlplane_db.migrations import upgrade
    upgrade(postgres_sync_url, chains=["platform", "events"])
    return postgres_sync_url


@pytest.fixture(scope="session")
def seed(migrated_sync_url: str) -> Seed:
    ta, tb = uuid.uuid4(), uuid.uuid4()
    ra, rb = uuid.uuid4(), uuid.uuid4()
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :n, true)"),
            {"id": ta, "n": f"tenant-{ta.hex[:8]}"},
        )
        cx.execute(
            text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :n, true)"),
            {"id": tb, "n": f"tenant-{tb.hex[:8]}"},
        )
        cx.execute(
            text(
                "INSERT INTO roles (id, tenant_id, name, permissions) "
                "VALUES (:id, :tid, 'member', '[]'::jsonb)"
            ),
            {"id": ra, "tid": ta},
        )
        cx.execute(
            text(
                "INSERT INTO roles (id, tenant_id, name, permissions) "
                "VALUES (:id, :tid, 'member', '[]'::jsonb)"
            ),
            {"id": rb, "tid": tb},
        )
        admin = uuid.uuid4()
        cx.execute(text("INSERT INTO roles (id, tenant_id, name, permissions) VALUES (:id, :tid, 'admin', '[]'::jsonb)"), {"id": admin, "tid": ta})
        cx.execute(text("INSERT INTO users (id, tenant_id, keycloak_sub, email, first_name, last_name, gender, is_active, role_id) VALUES (:id, :tid, :sub, 'actor@example.com', 'Actor', 'Admin', 'unspecified', true, :role)"), {"id": uuid.uuid4(), "tid": ta, "sub": "11111111-1111-1111-1111-111111111111", "role": admin})
    return Seed(ta, tb, ra, rb)


@pytest.fixture
def event_sink() -> list:
    return []


@pytest.fixture
def app(event_sink: list, migrated_sync_url: str, monkeypatch: pytest.MonkeyPatch):
    # normalize_database_url only rewrites bare postgresql:// → asyncpg
    db_url = migrated_sync_url
    if "+psycopg" in db_url:
        db_url = db_url.replace("postgresql+psycopg://", "postgresql://", 1)
    monkeypatch.setattr(api_config.settings, "database_url", db_url)
    monkeypatch.setattr(api_config.settings, "service_name", "user-service-test")

    from user_service.app import create_app

    return create_app(test_event_sink=event_sink)


@pytest.fixture
def auth_context(seed: Seed):
    """Default: actor in tenant A."""

    async def _user() -> AuthMeResponse:
        return AuthMeResponse(
            sub="11111111-1111-1111-1111-111111111111",
            email="actor@example.com",
            tenant_id=seed.ta,
            roles=["admin"],
            scopes=[],
        )

    async def _tenant() -> uuid.UUID:
        return seed.ta

    return _user, _tenant


@pytest.fixture
async def http_client(app, auth_context):
    _user, _tenant = auth_context
    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_current_tenant] = _tenant
    import httpx
    from asgi_lifespan import LifespanManager

    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_tenant, None)


@pytest.fixture
def tenant_headers(seed: Seed) -> dict[str, str]:
    return {
        "Authorization": "Bearer test-token",
        "X-Tenant-ID": str(seed.ta),
    }


@pytest.fixture(autouse=True)
def _published_payloads_follow_wire_contracts(monkeypatch):
    """Validate actual application publications without enabling a live transport."""
    from api.infrastructure.messaging.tenant_event_publisher import NoOpTenantEventPublisher
    from controlplane_events.contracts import validate_event_envelope
    from controlplane_events.envelope import ControlPlaneEventEnvelope
    original = NoOpTenantEventPublisher.publish
    async def checked(self, **kwargs):
        validate_event_envelope(ControlPlaneEventEnvelope(service='contract-test', **kwargs))
        return await original(self, **kwargs)
    monkeypatch.setattr(NoOpTenantEventPublisher, 'publish', checked)


@pytest.fixture(scope="session")
def closure_sync_url(migrated_sync_url):
    return migrated_sync_url


@pytest.fixture
def empty_authority_owner(migrated_sync_url):
    """A disposable nonprivileged User namespace, never the shared TEST database."""
    from importlib.resources import files
    from sqlalchemy.engine import make_url
    from controlplane_events.owner_schema import migrate
    from user_service.authority_migrate import install
    name='bootstrap_'+uuid.uuid4().hex;password=uuid.uuid4().hex
    root=create_engine(migrated_sync_url)
    with root.begin() as db:
        db.exec_driver_sql(f'CREATE ROLE "{name}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE')
        db.exec_driver_sql(f'CREATE SCHEMA "{name}" AUTHORIZATION "{name}"')
        db.exec_driver_sql(f'ALTER ROLE "{name}" SET search_path TO "{name}",public')
    engine=create_engine(make_url(migrated_sync_url).set(username=name,password=password))
    migrate(engine,revision='0001_owner_schema',ddl=Path(__file__).parent.joinpath('fixtures/owner-schema.sql').read_text())
    install(engine)
    try:yield engine
    finally:
        engine.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP SCHEMA "{name}" CASCADE');db.exec_driver_sql(f'DROP ROLE "{name}"')
        root.dispose()
