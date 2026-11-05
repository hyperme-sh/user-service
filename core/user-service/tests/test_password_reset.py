"""Fixed provider action and public RPC capability contracts; no reset tokens."""
import json
import asyncio
import uuid

import httpx
import pytest
from sqlalchemy import create_engine, text
from asgi_lifespan import LifespanManager

from user_service import password_reset as reset
from user_service.interfaces.api import operator_routes as routes

SECRET = "private-reset-credential-" + "r" * 40
OPS = "private-reset-capability-" + "o" * 40


@pytest.fixture
def worker_config(monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setenv("FASTAPI_ENV", "test")
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_URL", "https://issuer.example")
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_REALM", "reset")
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_CLIENT_ID", "operator-password-reset")
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET", SECRET)
    monkeypatch.setattr(settings, "keycloak_issuer", "https://issuer.example/realms/reset")


@pytest.fixture
def public_config(monkeypatch):
    monkeypatch.setenv("PASSWORD_RESET_AUTHORITY_URL", "https://reset-authority.example")
    monkeypatch.setenv("PASSWORD_RESET_OPERATIONS_TOKEN", OPS)
    monkeypatch.delenv("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET", raising=False)


@pytest.mark.parametrize("field,value", [
    ("id", "other-subject"), ("email", "other@example.com"), ("enabled", False),
    ("serviceAccountClientId", "service-identity"),
    ("federationLink", "external-storage"),
    ("federatedIdentities", [{"identityProvider": "external-idp"}]),
    ("username", "service-account-example"),
])
async def test_provider_rechecks_exact_subject_recipient_and_person(worker_config, field, value):
    calls = []
    def handle(request):
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "provider-access-token"})
        return httpx.Response(200, json={"id": "subject", "username": "person", "email": "person@example.com", "enabled": True, field: value})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        with pytest.raises(reset.PasswordResetTargetMismatch):
            await reset.KeycloakPasswordResetClient(client).send(subject="subject", email="person@example.com")
    assert [c.method for c in calls] == ["POST", "GET"]


async def test_provider_requests_only_expiring_password_action(worker_config):
    calls = []
    def handle(request):
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "provider-access-token"})
        if request.method == "GET":
            if request.url.path.endswith("/credentials"):
                return httpx.Response(200, json=[{"type": "password"}])
            return httpx.Response(200, json={"id": "subject", "username": "person", "email": "person@example.com", "enabled": True})
        return httpx.Response(204)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        await reset.KeycloakPasswordResetClient(client).send(subject="subject", email="person@example.com")
    action = calls[-1]
    assert action.url.path == "/admin/realms/reset/users/subject/execute-actions-email"
    assert dict(action.url.params) == {"lifespan": "600"}
    assert json.loads(action.content) == ["UPDATE_PASSWORD"]
    assert "person@example.com" not in action.content.decode()


@pytest.mark.parametrize("token", [None, True, "", "invalid\nvalue", "x" * 16385])
async def test_provider_bad_tokens_are_sanitized(worker_config, token):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"access_token": token})), trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable) as error:
            await reset.KeycloakPasswordResetClient(client).send(subject="subject", email="person@example.com")
    assert str(error.value) == "password_reset_unavailable"


@pytest.mark.parametrize("status", [200, 302, 403, 500, 503])
async def test_provider_non_acknowledgment_does_not_report_success(worker_config, status):
    def handle(request):
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "provider-access-token"})
        if request.method == "GET":
            if request.url.path.endswith("/credentials"):
                return httpx.Response(200, json=[{"type": "password"}])
            return httpx.Response(200, json={"id": "subject", "username": "person", "email": "person@example.com", "enabled": True})
        return httpx.Response(status, json={"error": "provider-private-diagnostic"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable) as error:
            await reset.KeycloakPasswordResetClient(client).send(subject="subject", email="person@example.com")
    assert "provider-private-diagnostic" not in str(error.value)


@pytest.mark.parametrize("name,value", [
    ("PASSWORD_RESET_KEYCLOAK_CLIENT_ID", "account-closure-worker"),
    ("PASSWORD_RESET_KEYCLOAK_REALM", "../master"),
    ("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET", "too-short"),
    ("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", SECRET),
    ("PASSWORD_RESET_OPERATIONS_TOKEN", SECRET),
])
async def test_provider_wrong_purpose_configuration_is_refused(worker_config, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.KeycloakPasswordResetClient(client)


async def test_provider_issuer_mismatch_is_refused(worker_config, monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setattr(settings, "keycloak_issuer", "https://other-issuer.example/realms/reset")
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.KeycloakPasswordResetClient(client)


async def test_provider_does_not_use_environment_proxies(worker_config):
    async with httpx.AsyncClient(trust_env=True) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.KeycloakPasswordResetClient(client)


async def test_provider_plaintext_remote_endpoint_is_refused_even_in_test(worker_config, monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_URL", "http://issuer.example")
    monkeypatch.setattr(settings, "keycloak_issuer", "http://issuer.example/realms/reset")
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.KeycloakPasswordResetClient(client)


async def test_public_process_refuses_provider_admin_credential(public_config, monkeypatch):
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET", SECRET)
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.PasswordResetAuthorityClient(client)


def test_operations_capability_is_not_the_actor_signing_key(public_config, monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setattr(settings, "api_key_exchange_jwt_secret", OPS)
    with pytest.raises(reset.PasswordResetUnavailable):
        reset.operations_secret()


async def test_provider_credential_is_not_the_actor_signing_key(worker_config, monkeypatch):
    from controlplane_api.config import settings
    monkeypatch.setattr(settings, "api_key_exchange_jwt_secret", SECRET)
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.KeycloakPasswordResetClient(client)


async def test_public_capability_does_not_use_environment_proxies(public_config):
    async with httpx.AsyncClient(trust_env=True) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.PasswordResetAuthorityClient(client)


async def test_public_plaintext_remote_authority_is_refused_even_in_test(public_config, monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "test")
    monkeypatch.setenv("PASSWORD_RESET_AUTHORITY_URL", "http://reset-authority.example")
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            reset.PasswordResetAuthorityClient(client)


@pytest.mark.parametrize("name", ["PASSWORD_RESET_DATABASE_URL", "PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET"])
async def test_public_app_will_not_start_with_private_credentials(monkeypatch, name):
    from user_service.app import create_app
    monkeypatch.setenv(name, "private-do-not-log")
    with pytest.raises(RuntimeError, match="Private password reset credentials") as error:
        async with LifespanManager(create_app(test_event_sink=[])):
            raise AssertionError("Public startup must reject private credentials")
    assert "private-do-not-log" not in str(error.value)


@pytest.mark.parametrize("result", [{"sent": False}, {"sent": 1}, {"sent": "true"},
                                   {"sent": True, "token": "must-not-be-forwarded"}, None])
async def test_public_capability_requires_exact_acknowledgment(public_config, result):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=result)), trust_env=False) as client:
        with pytest.raises(reset.PasswordResetUnavailable):
            await reset.PasswordResetAuthorityClient(client).send(tenant_id=uuid.uuid4(), user_id=uuid.uuid4(), email="person@example.com",
                                                                  authorization="Bearer actor-token")


@pytest.fixture
def reset_user(app, http_client, migrated_sync_url, seed, monkeypatch):
    uid = uuid.uuid4()
    email = f"{uid}@example.com"
    engine = create_engine(migrated_sync_url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO users (id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) "
                                "VALUES (:id,:tenant,:sub,:email,'Reset','Person','unspecified',true)"),
                           {"id": uid, "tenant": seed.ta, "sub": "bound-" + str(uid), "email": email})
    monkeypatch.setattr(routes, "require_support", lambda request: {"tenant_id": str(seed.ta), "sub": "operator"})
    from api.domain.operator.mail import MailQuota
    quota = MailQuota()
    monkeypatch.setattr(routes, "mail_quota", lambda: quota)
    try:
        yield uid, email, seed.ta, engine, quota
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM operator_audit WHERE target_id=:id"), {"id": str(uid)})
            connection.execute(text("DELETE FROM users WHERE id=:id"), {"id": uid})
        engine.dispose()


async def test_public_reset_binds_user_and_returns_no_link(http_client, tenant_headers, reset_user, public_config, respx_mock):
    uid, email, tenant, engine, quota = reset_user
    call = respx_mock.post("https://reset-authority.example/internal/password-reset").mock(return_value=httpx.Response(200, json={"sent": True}))
    response = await http_client.post("/api/v1/operator/mail/password-reset", headers=tenant_headers,
                                      json={"user_id": str(uid), "email": email, "reason": "requested by person"})
    assert response.status_code == 200
    assert response.json() == {"sent": True, "kind": "password_reset", "user_id": str(uid), "detail": None}
    assert json.loads(call.calls.last.request.content) == {"tenant_id": str(tenant), "user_id": str(uid), "email": email}
    assert call.calls.last.request.headers["X-Password-Reset-Token"] == OPS
    assert call.calls.last.request.headers["Authorization"] == tenant_headers["Authorization"]
    assert call.calls.last.request.headers["X-Tenant-ID"] == str(tenant)
    assert quota.used() == 1
    with engine.connect() as connection:
        row = connection.execute(text("SELECT actor,detail FROM operator_audit WHERE target_id=:id"), {"id": str(uid)}).one()
        assert row.actor == "operator"
        assert row.detail == {"kind": "password_reset", "provider": "keycloak"}


@pytest.mark.parametrize("reason", ["recipient", "inactive", "unbound", "deleted", "foreign"])
async def test_public_reset_refuses_wrong_local_binding(http_client, tenant_headers, reset_user, public_config, respx_mock, reason):
    uid, email, tenant, engine, quota = reset_user
    if reason == "recipient":
        email = "other@example.com"
    else:
        change = {"inactive": "is_active=false", "unbound": "keycloak_sub=NULL", "deleted": "deleted_at=now()", "foreign": "tenant_id=NULL"}[reason]
        with engine.begin() as connection:
            connection.execute(text(f"UPDATE users SET {change} WHERE id=:id"), {"id": uid})
    response = await http_client.post("/api/v1/operator/mail/password-reset", headers=tenant_headers,
                                      json={"user_id": str(uid), "email": email, "reason": "refused"})
    assert response.status_code in {404, 409}
    assert len(respx_mock.calls) == 0 and quota.used() == 0


async def test_public_reset_failure_is_opaque_and_not_success_audited(http_client, tenant_headers, reset_user, public_config, respx_mock):
    uid, email, tenant, engine, quota = reset_user
    respx_mock.post("https://reset-authority.example/internal/password-reset").mock(
        side_effect=httpx.ReadTimeout("provider-private-token-and-reset-link"))
    response = await http_client.post("/api/v1/operator/mail/password-reset", headers=tenant_headers,
                                      json={"user_id": str(uid), "email": email, "reason": "not confirmed"})
    assert response.status_code == 503
    assert "provider-private" not in response.text
    assert quota.used() == 0
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM operator_audit WHERE target_id=:id"), {"id": str(uid)}) == 0


async def test_configured_mailgun_cannot_fake_a_reset_success(http_client, tenant_headers, reset_user, monkeypatch, respx_mock):
    uid, email, _, _, quota = reset_user
    monkeypatch.delenv("PASSWORD_RESET_AUTHORITY_URL", raising=False)
    monkeypatch.delenv("PASSWORD_RESET_OPERATIONS_TOKEN", raising=False)
    for name, value in (("MAILGUN_API_KEY", "key-not-used"), ("MAILGUN_DOMAIN", "example.com"), ("MAILGUN_FROM", "support@example.com")):
        monkeypatch.setenv(name, value)
    response = await http_client.post("/api/v1/operator/mail/password-reset", headers=tenant_headers,
                                      json={"user_id": str(uid), "email": email, "reason": "not configured"})
    assert response.status_code == 503
    assert not respx_mock.calls and quota.used() == 0


async def test_reset_reserves_quota_before_awaiting_provider(http_client, tenant_headers, reset_user, public_config, respx_mock):
    uid, email, _, _, quota = reset_user
    quota.limit = 1
    started, release = asyncio.Event(), asyncio.Event()
    async def pending(request):
        started.set()
        await release.wait()
        return httpx.Response(200, json={"sent": True})
    call = respx_mock.post("https://reset-authority.example/internal/password-reset").mock(side_effect=pending)
    body = {"user_id": str(uid), "email": email, "reason": "quota test"}
    first = asyncio.create_task(http_client.post("/api/v1/operator/mail/password-reset", headers=tenant_headers, json=body))
    try:
        await asyncio.wait_for(started.wait(), timeout=3)
        second = await http_client.post("/api/v1/operator/mail/password-reset", headers=tenant_headers, json=body)
        assert second.status_code == 503
    finally:
        release.set()
    assert (await first).status_code == 200
    assert call.call_count == 1 and quota.used() == 1
