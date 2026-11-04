"""Real Keycloak disable/logout/delete effects, without changing deployed realms."""

import uuid

import httpx
import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy
from user_service.closure_idp import IdentityEffectUnavailable, KeycloakClosureClient


@pytest.fixture(scope="module")
def native_keycloak(require_docker):
    secret = uuid.uuid4().hex + uuid.uuid4().hex
    with (
        DockerContainer("quay.io/keycloak/keycloak:26.5@sha256:8d44614c74798322c4e07fbe0ecb15cfbb5879d69b484628555f58ade06f0d8c")
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", "closure-test-admin")
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", secret)
        .with_exposed_ports(8080)
        .with_command("start-dev --http-port=8080 --hostname-strict=false")
        # CI may run several real issuer fixtures concurrently. Bound startup
        # separately from the identity disable/logout/delete assertions below.
        .waiting_for(LogMessageWaitStrategy("Listening on:").with_startup_timeout(180))
    ) as container:
        base = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
        with httpx.Client(base_url=base, timeout=15, trust_env=False) as client:
            token = client.post(
                "/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "closure-test-admin",
                    "password": secret,
                },
            )
            token.raise_for_status()
            headers = {"Authorization": "Bearer " + token.json()["access_token"]}
            realm = "closure-native-" + uuid.uuid4().hex
            response = client.post(
                "/admin/realms",
                headers=headers,
                json={
                    "realm": realm,
                    "enabled": True,
                    "duplicateEmailsAllowed": True,
                    "loginWithEmailAllowed": False,
                },
            )
            assert response.status_code == 201
            root = f"/admin/realms/{realm}"
            for name, config in (
                (
                    "account-closure-worker",
                    {
                        "publicClient": False,
                        "secret": secret,
                        "serviceAccountsEnabled": True,
                        "standardFlowEnabled": False,
                        "directAccessGrantsEnabled": False,
                    },
                ),
                (
                    "closure-login",
                    {
                        "publicClient": True,
                        "directAccessGrantsEnabled": True,
                        "standardFlowEnabled": False,
                    },
                ),
            ):
                response = client.post(
                    root + "/clients",
                    headers=headers,
                    json={"clientId": name, "enabled": True, **config},
                )
                assert response.status_code == 201
            clients = client.get(root + "/clients", headers=headers).json()
            owner = next(
                row["id"] for row in clients if row["clientId"] == "account-closure-worker"
            )
            manager = next(
                row["id"] for row in clients if row["clientId"] == "realm-management"
            )
            account = client.get(
                root + f"/clients/{owner}/service-account-user", headers=headers
            ).json()["id"]
            roles = client.get(
                root + f"/clients/{manager}/roles", headers=headers
            ).json()
            response = client.post(
                root + f"/users/{account}/role-mappings/clients/{manager}",
                headers=headers,
                json=[
                    role
                    for role in roles
                    if role["name"] in {"manage-users", "view-users", "query-users"}
                ],
            )
            assert response.status_code == 204
            yield base, realm, secret, headers


@pytest.mark.parametrize("kind", ["human", "ai"])
async def test_native_exact_identity_disable_logout_and_delete(
    native_keycloak, monkeypatch, kind
):
    from controlplane_api.config import settings

    base, realm, secret, headers = native_keycloak
    monkeypatch.setenv("FASTAPI_ENV", "test")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_URL", base)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_REALM", realm)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_ID", "account-closure-worker")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", secret)
    monkeypatch.setattr(settings, "keycloak_issuer", base + "/realms/" + realm)
    root = f"/admin/realms/{realm}"
    username = kind + "-" + uuid.uuid4().hex
    other = username + "-other"
    password = uuid.uuid4().hex
    async with httpx.AsyncClient(base_url=base, timeout=15, trust_env=False) as client:
        subjects = []
        for name in (username, other):
            response = await client.post(
                root + "/users",
                headers=headers,
                json={
                    "username": name,
                    "email": username + "@example.invalid",
                    "enabled": True,
                    "emailVerified": True,
                    "firstName": "Native",
                    "lastName": "Test",
                    "attributes": {"principal_type": [kind]},
                    "credentials": [
                        {"type": "password", "value": password, "temporary": False}
                    ],
                },
            )
            assert response.status_code == 201, response.text
            subjects.append(response.headers["Location"].rsplit("/", 1)[1])
        login_data = {
            "client_id": "closure-login",
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        logged_in = await client.post(
            f"/realms/{realm}/protocol/openid-connect/token", data=login_data
        )
        assert logged_in.status_code == 200, logged_in.text
        refresh = logged_in.json()["refresh_token"]
        assert (
            len(
                (
                    await client.get(
                        root + f"/users/{subjects[0]}/sessions", headers=headers
                    )
                ).json()
            )
            == 1
        )
        owner = KeycloakClosureClient(client)
        await owner.disable(subjects[0])
        disabled = await client.get(root + f"/users/{subjects[0]}", headers=headers)
        assert disabled.json()["enabled"] is False
        assert (
            await client.get(root + f"/users/{subjects[0]}/sessions", headers=headers)
        ).json() == []
        assert (
            await client.post(
                f"/realms/{realm}/protocol/openid-connect/token", data=login_data
            )
        ).status_code == 400
        refreshed = await client.post(
            f"/realms/{realm}/protocol/openid-connect/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "closure-login",
                "refresh_token": refresh,
            },
        )
        assert refreshed.status_code == 400
        assert (
            await client.get(root + f"/users/{subjects[1]}", headers=headers)
        ).json()["enabled"] is True
        await owner.disable(subjects[0])
        with pytest.raises(IdentityEffectUnavailable):
            await owner.delete(subjects[0], disable_receipt=False)
        await owner.delete(subjects[0], disable_receipt=True)
        await owner.delete(subjects[0], disable_receipt=True)
        with pytest.raises(IdentityEffectUnavailable):
            await owner.disable(subjects[0])
        assert (
            await client.get(root + f"/users/{subjects[1]}", headers=headers)
        ).json()["enabled"] is True


async def test_native_ai_service_account_cannot_mint_after_disable(
    native_keycloak, monkeypatch
):
    from controlplane_api.config import settings

    base, realm, secret, headers = native_keycloak
    monkeypatch.setenv("FASTAPI_ENV", "test")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_URL", base)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_REALM", realm)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_ID", "account-closure-worker")
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", secret)
    monkeypatch.setattr(settings, "keycloak_issuer", base + "/realms/" + realm)
    root = f"/admin/realms/{realm}"
    name = "ai-service-" + uuid.uuid4().hex
    async with httpx.AsyncClient(base_url=base, timeout=15, trust_env=False) as client:
        created = await client.post(
            root + "/clients",
            headers=headers,
            json={
                "clientId": name,
                "enabled": True,
                "publicClient": False,
                "secret": secret,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
            },
        )
        assert created.status_code == 201
        identifier = created.headers["Location"].rsplit("/", 1)[1]
        account = await client.get(
            root + f"/clients/{identifier}/service-account-user", headers=headers
        )
        subject = account.json()["id"]
        data = {
            "grant_type": "client_credentials",
            "client_id": name,
            "client_secret": secret,
        }
        issued = await client.post(
            f"/realms/{realm}/protocol/openid-connect/token", data=data
        )
        assert issued.status_code == 200, issued.text
        owner = KeycloakClosureClient(client)
        await owner.disable(subject)
        denied = await client.post(
            f"/realms/{realm}/protocol/openid-connect/token", data=data
        )
        assert denied.status_code in {400, 401}
        assert "access_token" not in denied.json()
        assert denied.json()["error"] in {
            "invalid_client",
            "invalid_request",
            "invalid_grant",
            "unauthorized_client",
        }
        assert (await client.get(root + f"/users/{subject}", headers=headers)).json()[
            "enabled"
        ] is False
        await owner.delete(subject, disable_receipt=True)
        denied = await client.post(
            f"/realms/{realm}/protocol/openid-connect/token", data=data
        )
        assert denied.status_code in {400, 401}
        assert "access_token" not in denied.json()
        assert denied.json()["error"] in {
            "invalid_client",
            "invalid_request",
            "invalid_grant",
            "unauthorized_client",
        }
