"""Forwarding cannot manufacture actor authority or redirect secrets."""

import httpx
import pytest
from fastapi import FastAPI
from user_service import closure_proxy as proxy


@pytest.fixture
async def forwarding(monkeypatch):
    for name, value in {
        "ACCOUNT_CLOSURE_ACTIONS_ENABLED": "true", "ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED": "true",
        "ACCOUNT_CLOSURE_AUTHORITY_URL": "https://closure.internal",
        "ACCOUNT_CLOSURE_GUARD_TOKEN": "r" * 32, "ACCOUNT_CLOSURE_OPERATIONS_TOKEN": "w" * 32,
    }.items():
        monkeypatch.setenv(name, value)
    requests, response = [], [httpx.Response(202, json={"state": "closing"})]
    def receive(request):
        requests.append(request)
        return response[0]
    original = httpx.AsyncClient
    def upstream(**kwargs):
        return original(transport=httpx.MockTransport(receive), **kwargs)
    app = FastAPI()
    app.include_router(proxy.router, prefix="/api/v1")
    app.include_router(proxy.read_router, prefix="/api/v1")
    async with original(transport=httpx.ASGITransport(app=app), base_url="http://public") as client:
        monkeypatch.setattr(proxy.httpx, "AsyncClient", upstream)
        yield client, requests, response


async def test_original_bearer_only_no_caller_actor_tenant_or_guard(forwarding):
    client, requests, _ = forwarding
    result = await client.post("/api/v1/me/account-closure", json={"confirmation": "CLOSE MY ACCOUNT"},
        headers={"Authorization": "Bearer original", "X-Account-Lifecycle-Token": "r" * 32,
                 "X-Tenant-ID": "spoofed", "X-Actor-ID": "victim"})
    assert result.status_code == 202 and result.headers["cache-control"] == "no-store"
    request, = requests
    assert str(request.url) == "https://closure.internal/api/v1/me/account-closure"
    assert request.headers["authorization"] == "Bearer original"
    assert not any(name in request.headers for name in ("x-tenant-id", "x-actor-id", "x-account-lifecycle-token"))


async def test_reader_token_does_not_become_mutation_credential(forwarding):
    client, requests, response = forwarding
    response[0] = httpx.Response(401, json={"detail": "Native account token required"})
    result = await client.post("/api/v1/operator/account-closures",
        json={"subject": "victim", "confirmation": "CLOSE MY ACCOUNT"},
        headers={"X-Account-Lifecycle-Token": "r" * 32})
    assert result.status_code == 401
    assert requests[0].headers["authorization"] == ""
    assert "x-account-lifecycle-token" not in requests[0].headers


@pytest.mark.parametrize("path", ["scope", "grant-scope", "financial-scope", "permit", "check", "denials"])
async def test_reader_routes_preserve_tenant_without_forwarding_bearer(forwarding, path):
    client, requests, response = forwarding
    response[0] = httpx.Response(200, json={"allowed": False})
    headers = {"X-Account-Lifecycle-Token": "r" * 32, "X-Tenant-ID": "11111111-1111-1111-1111-111111111111",
               "Authorization": "Bearer never-forward-this"}
    url = "/api/v1/internal/account-lifecycle/" + path
    if path == "denials":
        result = await client.get(url, headers=headers)
    else:
        body = {"subject": "native"}
        if path != "check":
            body["closed_at"] = "2026-01-01T00:00:00Z"
        result = await client.post(url, headers=headers, json=body)
    assert result.status_code == 200
    request, = requests
    assert request.url.path == url
    assert request.headers["x-account-lifecycle-token"] == "r" * 32
    assert request.headers["x-tenant-id"] == headers["X-Tenant-ID"]
    assert "authorization" not in request.headers


@pytest.mark.parametrize("code", [301, 307, 500])
async def test_failures_do_not_redirect_or_expose_provider_body(forwarding, code):
    client, requests, response = forwarding
    response[0] = httpx.Response(code, json={"secret": "provider-diagnostic"}, headers={"Location": "https://attacker.example"})
    result = await client.get("/api/v1/operator/account-closures", params={"subject": "a&subject=victim"})
    assert result.status_code == 503 and "provider-diagnostic" not in result.text
    assert "location" not in result.headers and len(requests) == 1
    assert requests[0].url.params["subject"] == "a&subject=victim"


async def test_public_app_has_only_forwarding_closure_routes():
    from user_service.app import create_app
    app = create_app(test_event_sink=[])
    routes = [route for route in app.routes if "account-lifecycle" in getattr(route, "path", "")
              or getattr(route, "path", "").endswith(("/me/account-closure", "/operator/account-closures", "/operator/account-closures/hold"))]
    assert len(routes) == 10
    assert all(route.endpoint.__module__ == "user_service.closure_proxy" for route in routes)


@pytest.mark.parametrize("name", ["ACCOUNT_CLOSURE_WORKER_DATABASE_URL", "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET"])
async def test_public_startup_rejects_private_credentials(monkeypatch, name):
    from asgi_lifespan import LifespanManager
    from user_service.app import create_app
    monkeypatch.setenv(name, "private-credential")
    with pytest.raises(RuntimeError, match="Private closure credentials"):
        async with LifespanManager(create_app(test_event_sink=[])):
            pytest.fail("public process accepted private credentials")


async def test_large_native_snapshot_is_forwarded_with_a_bounded_reader_limit(forwarding):
    client, requests, response = forwarding
    snapshot = {"complete": True, "subjects": ["a" * 64] * 20_000}
    response[0] = httpx.Response(200, json=snapshot)
    result = await client.get("/api/v1/internal/account-lifecycle/denials",
                              headers={"X-Account-Lifecycle-Token": "r" * 32})
    assert result.status_code == 200 and result.json() == snapshot
    assert len(requests) == 1
    response[0] = httpx.Response(200, content=b"x" * (16 * 1024 * 1024 + 1))
    assert (await client.get("/api/v1/internal/account-lifecycle/denials",
                            headers={"X-Account-Lifecycle-Token": "r" * 32})).status_code == 503
