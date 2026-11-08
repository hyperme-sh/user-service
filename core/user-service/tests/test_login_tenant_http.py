"""Real signed issuer tokens and PostgreSQL; no shared fixture provisioning."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from test_scoped_authority import authority, login_context  # noqa: F401


@pytest.fixture
def login_issuer(login_context, monkeypatch):
    from auth_service import token_validation
    from controlplane_api.config import settings
    from controlplane_identity.security.keycloak_jwt import KeycloakJWTValidator

    _, claims = login_context
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public.update(kid="login-test", alg="RS256", use="sig")
    document = json.dumps({"keys": [public]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/jwks":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(document)))
            self.end_headers()
            self.wfile.write(document)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    validator = KeycloakJWTValidator(
        f"http://127.0.0.1:{server.server_port}/jwks", claims["iss"], "portal"
    )
    monkeypatch.setattr(settings, "auth_token_validation_mode", "jwks")
    monkeypatch.setattr(settings, "keycloak_client_id", "portal")
    monkeypatch.setattr(settings, "keycloak_allowed_client_ids", "portal,other-client")
    monkeypatch.setattr(settings, "keycloak_allowed_audiences", "portal")
    # Select the disposable issuer, retaining actual JWKS fetching, JWT decoding,
    # signature/audience/issuer checks and the normal Auth dependency chain.
    monkeypatch.setattr(token_validation, "get_keycloak_jwt_validator", lambda: validator)

    def token(*, changes=None, signing_key=None):
        payload = dict(claims, aud="portal", iat=int(time.time()), exp=int(time.time()) + 120,
                       amr=["mfa"], realm_access={"roles": ["admin"]}, permissions=["*"])
        payload.update(changes or {})
        return jwt.encode(payload, signing_key or key, algorithm="RS256", headers={"kid": "login-test"})

    try:
        yield token
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
async def login_http(authority, login_issuer, monkeypatch):
    from user_service.app import create_app

    app = create_app(test_event_sink=[])
    app.state.session_maker = authority.maker
    monkeypatch.setenv("AUTH_IDENTITY_OWNER_TOKEN", "disposable-login-test-service-credential")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://owner.test") as client:
        yield client


async def test_signed_first_login_discovers_and_enters_only_configured_tenant(authority, login_issuer, login_http):
    client = login_http
    headers = {"Authorization": "Bearer " + login_issuer()}
    before = await client.get("/api/v1/authority/contexts", headers=headers)
    assert before.status_code == 200 and before.json() == {"tenants": []}
    reply = await client.post("/api/v1/authority/login-tenant", headers=headers,
                              json={"tenant_id": str(authority.isolated), "role": "admin", "can_purchase_leases": True})
    assert reply.status_code == 204
    after = await client.get("/api/v1/authority/contexts", headers=headers)
    assert after.status_code == 200
    assert [t["id"] for t in after.json()["tenants"]] == [str(authority.tenant)]
    owner = {"Authorization": "Bearer disposable-login-test-service-credential"}
    switched = await client.post("/api/v1/internal/identity/tenant-switch", headers=owner,
                                 json={"user": {"sub": "new-person", "roles": ["admin"]}, "tenant_id": str(authority.tenant)})
    assert switched.status_code == 200
    grant = switched.json()
    assert grant["role_name"] == "user" and grant["permissions"] == [] and grant["groups"] == []
    member = await client.post("/api/v1/internal/identity/session-member", headers=owner,
                               json={"subject": "new-person", "tenant_id": str(authority.tenant)})
    assert member.status_code == 200 and member.json() == {"user_id": grant["user_id"]}
    assert (await client.post("/api/v1/internal/identity/session-member", headers=headers,
                              json={"subject": "new-person", "tenant_id": str(authority.tenant)})).status_code == 401


@pytest.mark.parametrize("failure,status", [("missing", 401), ("signature", 401),
    ("issuer", 401), ("client", 403), ("unverified", 403)])
async def test_login_http_refuses_untrusted_identity_without_profiles(login_issuer, login_http, failure, status):
    options = {}
    if failure == "signature":
        options["signing_key"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif failure == "issuer":
        options["changes"] = {"iss": "https://other.test/realm"}
    elif failure == "client":
        options["changes"] = {"azp": "other-client"}
    elif failure == "unverified":
        options["changes"] = {"email_verified": False}
    headers = {} if failure == "missing" else {"Authorization": "Bearer " + login_issuer(**options)}
    assert (await login_http.post("/api/v1/authority/login-tenant", headers=headers)).status_code == status
    current = await login_http.get("/api/v1/authority/contexts", headers={"Authorization": "Bearer " + login_issuer()})
    assert current.status_code == 200 and current.json() == {"tenants": []}
