import httpx
import pytest
from user_service.closure_directory import (
    DirectoryNotFound,
    DirectoryUnavailable,
    KeycloakClosureReader,
    ProtectedIdentity,
    identity_record,
    native_response,
)


@pytest.fixture
def configuration(monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setattr(settings, "keycloak_issuer", "https://idp.example/realms/hypermesh")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_URL", "https://idp.example")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_REALM", "hypermesh")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "r" * 32)
    monkeypatch.delenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", raising=False)


@pytest.mark.parametrize("marker", [None, False, [], ["false"], ["true"], {}])
def test_every_protection_marker_is_protected(marker):
    with pytest.raises(ProtectedIdentity):
        identity_record({"id": "subject", "enabled": True,
                         "attributes": {"account_closure_protected": marker}}, "subject")


@pytest.mark.parametrize("record", [{}, {"id": "other", "enabled": True},
    {"id": "subject", "enabled": 1}, {"id": "subject", "enabled": True, "attributes": []}])
def test_malformed_identity_never_becomes_a_target(record):
    with pytest.raises(DirectoryUnavailable):
        identity_record(record, "subject")


async def test_reader_exact_id_only_and_readonly(configuration):
    seen = []
    def handle(request):
        seen.append(request)
        if request.url.path.endswith("/token"):
            assert b"account-closure-reader" in request.content
            return httpx.Response(200, json={"access_token": "opaque"})
        assert request.method == "GET"
        assert request.url.path == "/admin/realms/hypermesh/users/subject"
        assert not request.url.query
        return httpx.Response(200, json={"id": "subject", "enabled": True, "email": "private"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        result = await KeycloakClosureReader(client).lookup("subject")
    assert result.subject == "subject" and result.enabled
    assert len(seen) == 2
    assert not hasattr(result, "email")


@pytest.mark.parametrize("status,error", [(404, DirectoryNotFound), (403, DirectoryUnavailable),
                                          (307, DirectoryUnavailable), (500, DirectoryUnavailable)])
async def test_reader_missing_or_unavailable(configuration, status, error):
    def handle(request):
        return (httpx.Response(200, json={"access_token": "opaque"}) if request.method == "POST"
                else httpx.Response(status))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        with pytest.raises(error):
            await KeycloakClosureReader(client).lookup("subject")


async def test_public_reader_rejects_privileged_credentials(configuration, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", "worker-secret")
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(DirectoryUnavailable):
            KeycloakClosureReader(client)


@pytest.mark.parametrize("response", [httpx.Response(200, content=b"x" * (1024 * 1024 + 1)),
    httpx.Response(200, content=b"private-not-json"),
    httpx.Response(200, json={}, headers={"Content-Encoding": "untrusted"})])
async def test_bounded_response_never_exposes_provider_payload(response):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response), trust_env=False) as client:
        with pytest.raises(DirectoryUnavailable) as exc:
            await native_response(client, "GET", "https://idp.example")
    assert str(exc.value) == "native_identity_directory_unavailable"
    assert exc.value.__cause__ is None
