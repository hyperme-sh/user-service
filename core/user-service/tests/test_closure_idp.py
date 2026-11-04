import httpx
import pytest
from user_service.closure_idp import IdentityEffectUnavailable, KeycloakClosureClient


@pytest.fixture
def configuration(monkeypatch):
    from controlplane_api.config import settings

    monkeypatch.setattr(
        settings, "keycloak_issuer", "https://idp.example/realms/hypermesh"
    )
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_URL", "https://idp.example")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_REALM", "hypermesh")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_ID", "account-closure-worker")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", "x" * 32)


async def test_exact_disable_logout_and_readback(configuration):
    seen = []

    def handle(request):
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "opaque"})
        assert request.headers["Authorization"] == "Bearer opaque"
        if request.method == "GET":
            return httpx.Response(200, json={"id": "exact-subject", "enabled": False})
        if request.method == "PUT":
            assert request.content == b'{"enabled":false}'
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        await KeycloakClosureClient(client).disable("exact-subject")
    root = "/admin/realms/hypermesh/users/exact-subject"
    assert seen[1:] == [("GET", root), ("PUT", root), ("POST", root + "/logout"), ("GET", root)]
    assert not any("email" in path for _, path in seen)


@pytest.mark.parametrize(
    "failure", ["missing", "logout", "readback", "redirect", "malformed"]
)
async def test_disable_never_acknowledges_unverified_state(configuration, failure):
    reads = 0

    def handle(request):
        nonlocal reads
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "secret-token"})
        if failure == "missing":
            return httpx.Response(404)
        if failure == "redirect":
            return httpx.Response(
                307, headers={"Location": "https://elsewhere.example"}
            )
        if request.url.path.endswith("/logout") and failure == "logout":
            return httpx.Response(500)
        if request.method == "GET":
            reads += 1
            if failure == "malformed":
                return httpx.Response(200, json=[])
            return httpx.Response(200, json={"id": "exact-subject", "enabled": reads == 1 or failure == "readback"})
        return httpx.Response(204)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        with pytest.raises(IdentityEffectUnavailable) as exc:
            await KeycloakClosureClient(client).disable("exact-subject")
    assert str(exc.value) == "identity_effect_unavailable"
    assert exc.value.__cause__ is None


async def test_delete_missing_is_idempotent_only_after_durable_disable(configuration):
    seen = []

    def handle(request):
        seen.append(request.method)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "opaque"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        adapter = KeycloakClosureClient(client)
        with pytest.raises(IdentityEffectUnavailable):
            await adapter.delete("subject", disable_receipt=False)
        assert seen == []
        await adapter.delete("subject", disable_receipt=True)
    assert seen == ["POST", "GET"]


async def test_wrong_realm_cannot_be_used_as_closure_proof(configuration, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_REALM", "other")
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(IdentityEffectUnavailable):
            KeycloakClosureClient(client)


@pytest.mark.parametrize("operation", ["disable", "delete"])
@pytest.mark.parametrize("record", [
    {"id": "subject", "enabled": False, "attributes": {"account_closure_protected": ["true"]}},
    {"id": "other-person", "enabled": False},
])
async def test_worker_never_mutates_protected_or_mismatched_identity(configuration, operation, record):
    seen = []
    def handle(request):
        seen.append(request.method)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "opaque"})
        return httpx.Response(200, json=record)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        adapter = KeycloakClosureClient(client)
        with pytest.raises(IdentityEffectUnavailable):
            if operation == "disable":
                await adapter.disable("subject")
            else:
                await adapter.delete("subject", disable_receipt=True)
    assert seen == ["POST", "GET"]
