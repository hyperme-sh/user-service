"""Actions use real durable retirement/holds; provider lookup is separately tested."""
import uuid
from contextlib import asynccontextmanager

import httpx
import pytest
from controlplane_db.models import IdentityRetirement
from fastapi import FastAPI
from jwt import InvalidTokenError
from test_closure_jobs import jobs, jobs_url  # noqa: F401
from user_service import closure_actions as actions
from user_service.closure_directory import DirectoryNotFound, ProtectedIdentity
from user_service.models import AccountLifecycle


@pytest.fixture
async def endpoint(jobs, monkeypatch):  # noqa: F811
    store, _ = jobs
    monkeypatch.setenv("ACCOUNT_CLOSURE_ACTIONS_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATOR_CLIENT_IDS", '["closure-ai"]')
    from controlplane_api.config import settings
    monkeypatch.setattr(settings, "keycloak_issuer", "https://idp.example/realms/test")
    subject = str(uuid.uuid4())
    lookups = []
    class Validator:
        async def validate(self, token):
            if token != "self":
                raise InvalidTokenError()
            return {"sub": subject}
        async def validate_closure_operator(self, token, *, client_ids):
            assert client_ids == frozenset({"closure-ai"})
            if token != "operator":
                raise InvalidTokenError()
            return {"sub": "native-operator", "iss": settings.keycloak_issuer,
                    "realm_access": {"roles": ["account:close"]}}
    class Reader:
        def __init__(self, client):
            pass
        async def lookup(self, target):
            lookups.append(target)
            if target == "missing":
                raise DirectoryNotFound()
            if target == "protected":
                raise ProtectedIdentity()
    monkeypatch.setattr(actions, "get_keycloak_jwt_validator", Validator)
    monkeypatch.setattr(actions, "KeycloakClosureReader", Reader)
    monkeypatch.setattr(actions, "jobs", lambda request: store)
    app = FastAPI()
    app.include_router(actions.router, prefix="/api/v1")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client, store, subject, lookups


async def test_self_literal_native_token_and_atomic_retirement(endpoint):
    client, store, subject, lookups = endpoint
    for body in [{"confirmation": "yes"}, {"confirmation": "CLOSE MY ACCOUNT", "subject": "victim"}]:
        reply = await client.post("/api/v1/me/account-closure", json=body, headers={"Authorization": "Bearer self"})
        assert reply.status_code == 422
    bad = await client.post("/api/v1/me/account-closure", json={"confirmation": "CLOSE MY ACCOUNT"},
                            headers={"Authorization": "Bearer wrapped"})
    assert bad.status_code == 401
    reply = await client.post("/api/v1/me/account-closure", json={"confirmation": "CLOSE MY ACCOUNT"},
                              headers={"Authorization": "Bearer self"})
    assert reply.status_code == 202 and reply.headers["cache-control"] == "no-store"
    assert reply.json()["subject"] == subject and lookups == [subject]
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        marker = await session.get(IdentityRetirement, subject)
        assert marker.retired_at == row.requested_at
        assert row.source == "self_service" and row.requested_by == subject
    assert "effects" not in reply.json() and "requested_by" not in reply.json()


@pytest.mark.parametrize("target,code", [("missing", 404), ("protected", 403)])
async def test_preflight_failure_creates_no_retirement(endpoint, target, code):
    client, store, _, lookups = endpoint
    reply = await client.post("/api/v1/operator/account-closures", json={"confirmation": "CLOSE MY ACCOUNT", "subject": target},
                              headers={"Authorization": "Bearer operator"})
    assert reply.status_code == code and lookups == [target]
    assert reply.headers["cache-control"] == "no-store"
    async with store.transaction() as session:
        assert await session.get(AccountLifecycle, target) is None
        assert await session.get(IdentityRetirement, target) is None


async def test_retry_deduplicates_before_provider_and_keeps_provenance(endpoint):
    client, store, subject, lookups = endpoint
    await store.request(subject, "original", "self_service")
    reply = await client.post("/api/v1/operator/account-closures", json={"confirmation": "CLOSE MY ACCOUNT", "subject": subject},
                              headers={"Authorization": "Bearer operator"})
    assert reply.status_code == 202 and lookups == []
    assert reply.json()["source"] == "self_service"
    async with store.transaction() as session:
        assert (await session.get(AccountLifecycle, subject)).requested_by == "original"


async def test_hold_requires_explicit_matching_release(endpoint):
    client, store, subject, _ = endpoint
    await store.request(subject, subject, "self_service")
    async def hold(value, reference):
        return await client.post("/api/v1/operator/account-closures/hold", json={"subject": subject, "hold": value, "reference": reference},
                                 headers={"Authorization": "Bearer operator"})
    assert (await hold(True, "case-123")).json()["financial_hold"] is True
    assert (await hold(False, "other")).status_code == 409
    assert (await hold(True, "other")).status_code == 409
    assert (await hold(False, "case-123")).json()["financial_hold"] is False


@pytest.mark.parametrize("flag", ["ACCOUNT_CLOSURE_ACTIONS_ENABLED", "ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED"])
async def test_both_activation_gates_required(endpoint, monkeypatch, flag):
    client, _, _, lookups = endpoint
    monkeypatch.setenv(flag, "false")
    reply = await client.post("/api/v1/me/account-closure", json={"confirmation": "CLOSE MY ACCOUNT"},
                              headers={"Authorization": "Bearer self"})
    assert reply.status_code == 503 and lookups == []


async def test_no_database_transaction_crosses_preflight(endpoint, monkeypatch):
    client, store, subject, _ = endpoint
    original = store.transaction
    active = 0
    @asynccontextmanager
    async def observed(*args, **kwargs):
        nonlocal active
        async with original(*args, **kwargs) as session:
            active += 1
            try:
                yield session
            finally:
                active -= 1
    monkeypatch.setattr(store, "transaction", observed)
    class Reader:
        def __init__(self, client):
            pass
        async def lookup(self, target):
            assert active == 0
    monkeypatch.setattr(actions, "KeycloakClosureReader", Reader)
    reply = await client.post("/api/v1/operator/account-closures", json={"confirmation": "CLOSE MY ACCOUNT", "subject": subject},
                              headers={"Authorization": "Bearer operator"})
    assert reply.status_code == 202


async def test_legacy_root_requires_reconciliation_without_provider_lookup(endpoint):
    client, store, subject, lookups = endpoint
    await store.request(subject, subject, "self_service")
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        row.effects = {}
    reply = await client.post("/api/v1/operator/account-closures",
        json={"confirmation": "CLOSE MY ACCOUNT", "subject": subject},
        headers={"Authorization": "Bearer operator"})
    assert reply.status_code == 409 and lookups == []
    assert reply.headers["cache-control"] == "no-store"


async def test_retirement_only_requires_reconciliation_without_provider_lookup(endpoint):
    client, store, subject, lookups = endpoint
    async with store.transaction() as session:
        session.add(IdentityRetirement(subject=subject, retired_at=await store._database_now(session)))
    reply = await client.post('/api/v1/me/account-closure', json={'confirmation': 'CLOSE MY ACCOUNT'},
                              headers={'Authorization': 'Bearer self'})
    assert reply.status_code == 409 and not lookups
    async with store.transaction() as session:
        assert await session.get(AccountLifecycle, subject) is None
