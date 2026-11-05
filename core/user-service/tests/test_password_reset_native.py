"""Real Keycloak SMTP delivery, password redemption, expiry and replay refusal."""
import asyncio
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
import ipaddress
from pathlib import Path
import re
import ssl
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urljoin, urlparse
import uuid

import httpx
import jwt
import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.network import Network
from testcontainers.core.wait_strategies import LogMessageWaitStrategy
from asgi_lifespan import LifespanManager
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from user_service.password_reset import (
    KeycloakPasswordResetClient, PasswordResetTargetMismatch, PasswordResetUnavailable,
)

PYTHON = "python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f"
KEYCLOAK = "quay.io/keycloak/keycloak:26.5@sha256:8d44614c74798322c4e07fbe0ecb15cfbb5879d69b484628555f58ade06f0d8c"


@pytest.fixture(scope="module")
def reset_issuer(require_docker, tmp_path_factory):
    bootstrap, secret = uuid.uuid4().hex * 2, uuid.uuid4().hex * 2
    directory = tmp_path_factory.mktemp("reset-issuer-tls")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Native reset CA")])
    now = datetime.now(UTC)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    ca_path, cert_path, key_path = [directory / n for n in ("ca.pem", "server.pem", "server.key")]
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    key_path.chmod(0o644)  # Disposable fixture key, readable by Keycloak's container UID.
    tls = ssl.create_default_context(cafile=str(ca_path))
    with Network() as network:
        with (DockerContainer(PYTHON).with_network(network).with_network_aliases("reset-smtp")
              .with_volume_mapping(str(Path(__file__).parent / "fixtures/reset_smtp.py"), "/smtp_capture.py", mode="ro")
              .with_exposed_ports(8025).with_command("python /smtp_capture.py")
              .waiting_for(LogMessageWaitStrategy("SMTP capture ready").with_startup_timeout(60))) as smtp:
            host = smtp.get_container_host_ip()
            try:
                host_name = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                host_name = x509.DNSName(host)
            cert = leaf.add_extension(x509.SubjectAlternativeName([host_name]), critical=False).sign(ca_key, hashes.SHA256())
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            cert_path.chmod(0o644)
            with (DockerContainer(KEYCLOAK).with_network(network)
                  .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", "reset-test-admin")
                  .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", bootstrap).with_exposed_ports(8443)
                  .with_volume_mapping(str(cert_path), "/tls/server.pem", mode="ro")
                  .with_volume_mapping(str(key_path), "/tls/server.key", mode="ro")
                  .with_command("start-dev --http-enabled=false --https-port=8443 --hostname-strict=false "
                                "--https-certificate-file=/tls/server.pem --https-certificate-key-file=/tls/server.key")
                  .waiting_for(LogMessageWaitStrategy("Listening on:").with_startup_timeout(180))) as issuer:
                base = f"https://{issuer.get_container_host_ip()}:{issuer.get_exposed_port(8443)}"
                capture = f"http://{smtp.get_container_host_ip()}:{smtp.get_exposed_port(8025)}"
                realm = "reset-native-" + uuid.uuid4().hex
                with httpx.Client(base_url=base, timeout=15, trust_env=False, verify=tls) as client:
                    token = client.post("/realms/master/protocol/openid-connect/token", data={
                        "grant_type": "password", "client_id": "admin-cli",
                        "username": "reset-test-admin", "password": bootstrap,
                    })
                    assert token.status_code == 200
                    headers = {"Authorization": "Bearer " + token.json()["access_token"]}
                    created = client.post("/admin/realms", headers=headers, json={
                        "realm": realm, "enabled": True, "resetPasswordAllowed": True,
                        "loginWithEmailAllowed": False,
                        "smtpServer": {"host": "reset-smtp", "port": "2525", "from": "reset@example.com",
                                       "auth": "false", "ssl": "false", "starttls": "false"},
                    })
                    assert created.status_code == 201
                    root = f"/admin/realms/{realm}"
                    for config in (
                        {"clientId": "operator-password-reset", "publicClient": False, "secret": secret,
                         "serviceAccountsEnabled": True, "standardFlowEnabled": False},
                        {"clientId": "reset-login", "publicClient": True, "directAccessGrantsEnabled": True,
                         "standardFlowEnabled": False},
                    ):
                        assert client.post(root + "/clients", headers=headers, json={"enabled": True, **config}).status_code == 201
                    clients = client.get(root + "/clients", headers=headers).json()
                    owner = next(c["id"] for c in clients if c["clientId"] == "operator-password-reset")
                    manager = next(c["id"] for c in clients if c["clientId"] == "realm-management")
                    account = client.get(root + f"/clients/{owner}/service-account-user", headers=headers).json()["id"]
                    roles = client.get(root + f"/clients/{manager}/roles", headers=headers).json()
                    assert client.post(root + f"/users/{account}/role-mappings/clients/{manager}", headers=headers,
                                       json=[r for r in roles if r["name"] in {"manage-users", "view-users"}]).status_code == 204
                yield SimpleNamespace(base=base, realm=realm, capture=capture, secret=secret,
                                      headers=headers, tls=tls, ca_path=ca_path, service_account=account,
                                      bootstrap=bootstrap)


@pytest.fixture
def reset_config(reset_issuer, monkeypatch):
    from controlplane_api.config import settings
    s = reset_issuer
    # Administrative fixture credentials can expire while other native owners
    # migrate/start. Refresh them without changing action-token expiry policy.
    with httpx.Client(trust_env=False, verify=s.tls, timeout=15) as client:
        token = client.post(s.base + "/realms/master/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": "admin-cli",
            "username": "reset-test-admin", "password": s.bootstrap,
        })
        assert token.status_code == 200
        s.headers = {"Authorization": "Bearer " + token.json()["access_token"]}
    monkeypatch.setenv("FASTAPI_ENV", "test")
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_URL", s.base)
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_REALM", s.realm)
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_CLIENT_ID", "operator-password-reset")
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET", s.secret)
    monkeypatch.setenv("PASSWORD_RESET_KEYCLOAK_CA", str(s.ca_path))
    monkeypatch.setattr(settings, "keycloak_issuer", s.base + "/realms/" + s.realm)
    return s


async def create_user(s):
    name = "person-" + uuid.uuid4().hex
    password = "Initial-" + uuid.uuid4().hex
    async with httpx.AsyncClient(base_url=s.base, trust_env=False, verify=s.tls) as client:
        response = await client.post(f"/admin/realms/{s.realm}/users", headers=s.headers, json={
            "username": name, "email": name + "@example.com", "enabled": True,
            "firstName": "Native", "lastName": "Reset", "emailVerified": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        })
        assert response.status_code == 201
    return response.headers["Location"].rsplit("/", 1)[1], name, password


async def captured(s):
    async with httpx.AsyncClient(trust_env=False) as client:
        return (await client.get(s.capture)).json()


async def request_action(s, subject, email):
    before = len(await captured(s))
    async with httpx.AsyncClient(trust_env=False, timeout=15, verify=s.tls) as client:
        await KeycloakPasswordResetClient(client).send(subject=subject, email=email)
    rows = await captured(s)
    assert len(rows) == before + 1
    row = rows[-1]
    assert row["recipients"] == [email]
    url, = re.findall(r"https?://[^\s<>]+/login-actions/action-token\?[^\s<>]+", row["text"])
    return url


class Actions(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.links = [], []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action"), "id": attrs.get("id"), "fields": {}}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None and attrs.get("name"):
            self.current["fields"][attrs["name"]] = attrs.get("value", "")
        elif tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


async def redeem(client, link, password):
    response = await client.get(link)
    for _ in range(6):
        page = Actions()
        page.feed(response.text)
        if page.forms:
            form = page.forms[0]
            fields = form["fields"]
            password_form = "password-new" in fields
            if password_form:
                fields.update({"password-new": password, "password-confirm": password})
            response = await client.post(urljoin(str(response.url), form["action"]), data=fields)
            if password_form:
                return
        else:
            links = [urljoin(str(response.url), x) for x in page.links if "/login-actions/" in x]
            assert links, "Expected native action confirmation or password form"
            response = await client.get(links[0])
    raise AssertionError("Native password form was not reached")


async def login(s, username, password):
    async with httpx.AsyncClient(trust_env=False, verify=s.tls) as client:
        return await client.post(s.base + f"/realms/{s.realm}/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": "reset-login", "username": username, "password": password,
        })


async def test_native_password_action_delivers_redeems_and_is_single_use(reset_config):
    s = reset_config
    subject, username, old = await create_user(s)
    other_subject, other_name, other_password = await create_user(s)
    link = await request_action(s, subject, username + "@example.com")
    token = parse_qs(urlparse(link).query)["key"][0]
    # Inspection only: actual redemption below is verified by Keycloak, not this decode.
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == subject and claims["exp"] - claims["iat"] <= 600
    changed = "Changed-" + uuid.uuid4().hex
    async with httpx.AsyncClient(follow_redirects=True, trust_env=False, verify=s.tls) as browser:
        await redeem(browser, link, changed)
    assert (await login(s, username, changed)).status_code == 200
    assert (await login(s, username, old)).status_code == 401
    assert (await login(s, other_name, other_password)).status_code == 200
    async with httpx.AsyncClient(follow_redirects=True, trust_env=False, verify=s.tls) as browser:
        replay = await browser.get(link)
        page = Actions(); page.feed(replay.text)
        assert not any("password-new" in form["fields"] for form in page.forms)
        assert replay.status_code >= 400


async def test_native_password_action_expiry_is_enforced(reset_config, monkeypatch):
    from user_service import password_reset
    s = reset_config
    subject, username, old = await create_user(s)
    monkeypatch.setattr(password_reset, "RESET_LIFESPAN_SECONDS", 1)
    link = await request_action(s, subject, username + "@example.com")
    claims = jwt.decode(parse_qs(urlparse(link).query)["key"][0], options={"verify_signature": False})
    while time.time() <= claims["exp"] + 1:
        await asyncio.sleep(0.1)
    async with httpx.AsyncClient(follow_redirects=True, trust_env=False, verify=s.tls) as browser:
        expired = await browser.get(link)
        page = Actions(); page.feed(expired.text)
        assert expired.status_code >= 400
        assert not any("password-new" in form["fields"] for form in page.forms)
    assert (await login(s, username, old)).status_code == 200


async def test_native_wrong_recipient_and_missing_subject_send_nothing(reset_config):
    s = reset_config
    subject, username, _ = await create_user(s)
    before = await captured(s)
    async with httpx.AsyncClient(trust_env=False, verify=s.tls) as client:
        owner = KeycloakPasswordResetClient(client)
        for sub, email in ((subject, "wrong@example.com"), (str(uuid.uuid4()), username + "@example.com")):
            with pytest.raises(PasswordResetTargetMismatch):
                await owner.send(subject=sub, email=email)
    assert await captured(s) == before


async def test_native_brokered_identity_does_not_gain_a_local_reset(reset_config):
    s = reset_config
    subject, username, _ = await create_user(s)
    root = s.base + f"/admin/realms/{s.realm}"
    before = await captured(s)
    async with httpx.AsyncClient(trust_env=False, verify=s.tls) as client:
        assert (await client.post(root + "/identity-provider/instances", headers=s.headers, json={
            "providerId": "oidc", "alias": "native-broker", "enabled": True,
            "config": {"clientId": "unused-native-client", "authorizationUrl": "https://unused.example/auth",
                       "tokenUrl": "https://unused.example/token", "jwksUrl": "https://unused.example/jwks"},
        })).status_code == 201
        assert (await client.post(root + f"/users/{subject}/federated-identity/native-broker", headers=s.headers,
                                  json={"identityProvider": "native-broker", "userId": "external-id", "userName": "external-person"})).status_code == 204
        with pytest.raises(PasswordResetTargetMismatch):
            await KeycloakPasswordResetClient(client).send(subject=subject, email=username + "@example.com")
    assert await captured(s) == before


async def test_native_service_account_does_not_gain_a_password_action(reset_config):
    s = reset_config
    before = await captured(s)
    email = "native-service-account@example.com"
    async with httpx.AsyncClient(trust_env=False, verify=s.tls) as client:
        assert (await client.put(s.base + f"/admin/realms/{s.realm}/users/{s.service_account}",
                                 headers=s.headers, json={"email": email})).status_code == 204
        with pytest.raises(PasswordResetTargetMismatch):
            await KeycloakPasswordResetClient(client).send(subject=s.service_account, email=email)
    assert await captured(s) == before


async def test_native_passwordless_identity_does_not_gain_a_password_action(reset_config):
    s = reset_config
    subject, username, _ = await create_user(s)
    url = s.base + f"/admin/realms/{s.realm}/users/{subject}/credentials"
    before = await captured(s)
    async with httpx.AsyncClient(trust_env=False, verify=s.tls) as client:
        credentials = (await client.get(url, headers=s.headers)).json()
        for credential in credentials:
            if credential["type"] == "password":
                assert (await client.delete(url + "/" + credential["id"], headers=s.headers)).status_code == 204
        with pytest.raises(PasswordResetTargetMismatch):
            await KeycloakPasswordResetClient(client).send(subject=subject, email=username + "@example.com")
    assert await captured(s) == before


async def test_native_issuer_ca_must_be_trusted(reset_config):
    s = reset_config
    before = await captured(s)
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(PasswordResetUnavailable):
            await KeycloakPasswordResetClient(client).send(subject=str(uuid.uuid4()), email="person@example.com")
    assert await captured(s) == before


async def test_native_smtp_failure_is_not_acknowledged_as_success(reset_config):
    s = reset_config
    subject, username, _ = await create_user(s)
    before = await captured(s)
    root = s.base + f"/admin/realms/{s.realm}"
    async with httpx.AsyncClient(trust_env=False, verify=s.tls) as client:
        smtp = (await client.get(root, headers=s.headers)).json()["smtpServer"]
        try:
            assert (await client.put(root, headers=s.headers, json={"smtpServer": {**smtp, "port": "9"}})).status_code == 204
            with pytest.raises(PasswordResetUnavailable):
                await KeycloakPasswordResetClient(client).send(subject=subject, email=username + "@example.com")
        finally:
            assert (await client.put(root, headers=s.headers, json={"smtpServer": smtp})).status_code == 204
    assert await captured(s) == before


@pytest.fixture
async def reset_store(reset_config, migrated_sync_url, monkeypatch):
    from controlplane_api.config import settings
    from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt
    s = reset_config
    subject, username, old_password = await create_user(s)
    tenant, uid = uuid.uuid4(), uuid.uuid4()
    role, password = "reset_reader_" + uuid.uuid4().hex, uuid.uuid4().hex * 2
    engine = create_engine(migrated_sync_url)
    with engine.begin() as cx:
        cx.execute(text("INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)"), {"id": tenant, "name": str(tenant)})
        cx.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) "
                        "VALUES(:id,:tenant,:subject,:email,'Reset','Native','unspecified',true)"),
                   {"id": uid, "tenant": tenant, "subject": subject, "email": username + "@example.com"})
        # Only generated identifiers/hex passwords are interpolated into role DDL.
        cx.execute(text(f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"))
        cx.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        cx.execute(text(f"GRANT SELECT ON users,tenants TO {role}"))
    dsn = make_url(migrated_sync_url).set(drivername="postgresql+asyncpg", username=role, password=password)
    monkeypatch.setenv("PASSWORD_RESET_DATABASE_URL", dsn.render_as_string(hide_password=False))
    guard = uuid.uuid4().hex * 2
    monkeypatch.setenv("PASSWORD_RESET_OPERATIONS_TOKEN", guard)
    monkeypatch.setattr(settings, "api_key_exchange_jwt_secret", uuid.uuid4().hex * 2)
    def actor_headers(tenant_id):
        token = mint_tenant_session_jwt(claims={"sub": "reset-test-operator",
            "permissions": ["operator:console", "operator:support"]}, tenant_id=tenant_id)
        return {"Authorization": "Bearer " + token, "X-Tenant-ID": str(tenant_id),
                "X-Password-Reset-Token": guard}
    try:
        yield SimpleNamespace(issuer=s, tenant=tenant, user=uid, email=username + "@example.com",
                              username=username, old_password=old_password, guard=guard, engine=engine, role=role,
                              headers=actor_headers(tenant), actor_headers=actor_headers)
    finally:
        with engine.begin() as cx:
            cx.execute(text("DELETE FROM users WHERE id=:id"), {"id": uid})
            cx.execute(text("DELETE FROM tenants WHERE id=:id"), {"id": tenant})
            cx.execute(text(f"DROP OWNED BY {role}"))
            cx.execute(text(f"DROP ROLE {role}"))
        engine.dispose()


async def test_private_authority_only_sends_bound_action_with_readonly_database(reset_store):
    from user_service.password_reset_authority import create_app
    s = reset_store
    app = create_app()
    before = len(await captured(s.issuer))
    payload = {"tenant_id": str(s.tenant), "user_id": str(s.user), "email": s.email}
    async with LifespanManager(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://private-reset") as client:
            denied = await client.post("/internal/password-reset", json=payload)
            assert denied.status_code == 403
            assert (await client.post("/internal/password-reset", json=payload,
                                      headers={k: v for k, v in s.headers.items() if k != "X-Password-Reset-Token"})).status_code == 403
            assert (await client.post("/internal/password-reset", json=payload,
                                      headers={"X-Password-Reset-Token": s.guard})).status_code == 401
            headers = s.headers
            assert (await client.get("/internal/password-reset", headers=headers)).status_code == 404
            assert (await client.get("/api/v1/users", headers=headers)).status_code == 404
            assert (await client.post("/internal/password-reset", headers=headers,
                                      json={**payload, "actions": ["VERIFY_EMAIL"]})).status_code == 422
            foreign = await client.post("/internal/password-reset", headers=headers,
                                        json={**payload, "tenant_id": str(uuid.uuid4())})
            assert foreign.status_code == 403
            other = uuid.uuid4()
            assert (await client.post("/internal/password-reset", headers=s.actor_headers(other),
                                      json={**payload, "tenant_id": str(other)})).status_code == 409
            assert len(await captured(s.issuer)) == before
            response = await client.post("/internal/password-reset", headers=headers, json=payload)
            assert response.status_code == 200
            assert response.json() == {"sent": True}
            assert response.headers["Cache-Control"] == "no-store"
    rows = await captured(s.issuer)
    assert len(rows) == before + 1 and rows[-1]["recipients"] == [s.email]


@pytest.mark.parametrize("grant", ["table", "column", "bypassrls"])
async def test_private_authority_rejects_a_writable_database_role(reset_store, grant):
    from user_service.password_reset_authority import create_app
    s = reset_store
    with s.engine.begin() as cx:
        command = {"table": f"GRANT UPDATE ON users TO {s.role}",
                   "column": f"GRANT UPDATE(email) ON users TO {s.role}",
                   "bypassrls": f"ALTER ROLE {s.role} BYPASSRLS"}[grant]
        cx.execute(text(command))
    with pytest.raises(PasswordResetUnavailable):
        async with LifespanManager(create_app()):
            raise AssertionError("Writable role must not start private authority")
