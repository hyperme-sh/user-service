"""Private HTTP startup, native claims and session isolation on disposable PG."""

import uuid

import httpx
import pytest
from asgi_lifespan import LifespanManager
from jwt import InvalidTokenError
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service import closure_actions, closure_authority
from user_service.closure_worker import WorkerUnavailable
from user_service.models import AccountLifecycle


@pytest.fixture
async def private(jobs_url, monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setattr(settings, "keycloak_issuer", "https://idp.example/realms/test")
    for name, value in {
        "ACCOUNT_CLOSURE_AUTHORITY_ENABLED": "true", "ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED": "true",
        "ACCOUNT_CLOSURE_ACTIONS_ENABLED": "true", "ACCOUNT_CLOSURE_KEYCLOAK_URL": "https://idp.example",
        "ACCOUNT_CLOSURE_KEYCLOAK_REALM": "test", "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_ID": "account-closure-worker",
        "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET": "k" * 32,
        "ACCOUNT_CLOSURE_GUARD_TOKEN": "r" * 32, "ACCOUNT_CLOSURE_OPERATIONS_TOKEN": "w" * 32,
        "ACCOUNT_CLOSURE_WORKER_DATABASE_URL": jobs_url.replace("+psycopg", "+asyncpg"),
    }.items():
        monkeypatch.setenv(name, value)
    subject = str(uuid.uuid4())
    lookups, validated = [], []
    def provider(request):
        lookups.append(request)
        if request.url.path.endswith("/token"):
            assert b"account-closure-worker" in request.content
            return httpx.Response(200, json={"access_token": "worker-native-token"})
        assert request.method == "GET"
        assert request.url.path.endswith("/users/" + subject)
        return httpx.Response(200, json={"id": subject, "enabled": True})
    class Validator:
        async def validate(self, token):
            validated.append(token)
            if token != "native-token":
                raise InvalidTokenError()
            return {"sub": subject}
    monkeypatch.setattr(closure_actions, "get_keycloak_jwt_validator", Validator)
    def forbidden_global():
        raise AssertionError("private request used the public process session maker")
    monkeypatch.setattr("user_service.middleware.get_session_maker", forbidden_global)
    original = httpx.AsyncClient
    def upstream(**kwargs):
        return original(transport=httpx.MockTransport(provider), **kwargs)
    monkeypatch.setattr(closure_authority.httpx, "AsyncClient", upstream)
    app = closure_authority.create_app()
    async with (
        LifespanManager(app),
        original(transport=httpx.ASGITransport(app=app), base_url="http://private") as client,
    ):
        yield client, app, subject, lookups, validated


async def test_private_native_token_creates_real_root_and_serves_denial(private, jobs):
    client, app, subject, lookups, validated = private
    result = await client.post("/api/v1/me/account-closure", headers={"Authorization": "Bearer native-token",
        "X-Actor-ID": "victim"}, json={"confirmation": "CLOSE MY ACCOUNT"})
    assert result.status_code == 202 and result.json()["subject"] == subject
    assert validated == ["native-token"] and len(lookups) == 2
    assert app.state.session_maker is app.state.closure_session_maker
    store, _ = jobs
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.requested_by == subject and row.source == "self_service"
    response = await client.post("/api/v1/internal/account-lifecycle/check", json={"subject": subject},
                                headers={"X-Account-Lifecycle-Token": "r" * 32})
    assert response.status_code == 200 and response.json() == {"blocked": True}
    assert (await client.get("/docs")).status_code == 404
    assert (await client.get("/api/v1/users")).status_code == 404


async def test_private_reader_or_spoofed_actor_cannot_close(private, jobs):
    client, _, subject, lookups, validated = private
    for headers in [{"X-Account-Lifecycle-Token": "r" * 32},
                    {"Authorization": "Bearer forged", "X-Actor-ID": subject}]:
        response = await client.post("/api/v1/me/account-closure", headers=headers,
                                     json={"confirmation": "CLOSE MY ACCOUNT"})
        assert response.status_code == 401
    assert validated == ["forged"] and lookups == []
    store, _ = jobs
    async with store.transaction() as session:
        assert await session.get(AccountLifecycle, subject) is None


@pytest.mark.parametrize("flag", ["ACCOUNT_CLOSURE_AUTHORITY_ENABLED", "ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED"])
async def test_private_authority_startup_requires_both_gates(monkeypatch, flag):
    monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv(flag, "false")
    with pytest.raises(WorkerUnavailable):
        async with LifespanManager(closure_authority.create_app()):
            pytest.fail("unconfigured authority started")


@pytest.mark.parametrize("tenant", [None, "11111111-1111-1111-1111-111111111111"])
async def test_retirement_only_identity_stays_blocked_without_creating_a_root(private, jobs, tenant):
    from controlplane_tenancy.tenant_membership import retire_identity
    from sqlalchemy import text
    client, _, subject, lookups, _ = private
    store, _ = jobs
    headers = {"X-Account-Lifecycle-Token": "r" * 32}
    if tenant is not None:
        headers["X-Tenant-ID"] = tenant
    async def check():
        return await client.post("/api/v1/internal/account-lifecycle/check", headers=headers, json={"subject": subject})
    assert (await check()).json() == {"blocked": False}
    async with store.transaction() as session:
        await retire_identity(session, subject, await session.scalar(text("SELECT transaction_timestamp()")))
    response = await check()
    assert response.status_code == 200 and response.json() == {"blocked": True}
    result = await client.post("/api/v1/me/account-closure", headers={"Authorization": "Bearer native-token"},
                               json={"confirmation": "CLOSE MY ACCOUNT"})
    assert result.status_code == 409 and lookups == []
    async with store.transaction() as session:
        assert await session.get(AccountLifecycle, subject) is None
