"""Owned loopback TLS exercises public forwarding to the real private app."""

import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from httpx import AsyncClient as RealClient
from test_closure_authority import private as private  # noqa: PLC0414
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service import closure_health, closure_proxy, closure_runtime
from user_service.closure_transport import authority_verify
from user_service.closure_worker import WorkerUnavailable


@pytest.fixture
def certificates(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "account-closure-authority")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=15))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.DNSName("account-closure-authority")]), critical=False).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    key_path.chmod(0o600)
    monkeypatch.setenv("ACCOUNT_CLOSURE_TLS_CERT_FILE", str(cert_path))
    monkeypatch.setenv("ACCOUNT_CLOSURE_TLS_KEY_FILE", str(key_path))
    monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_CA_FILE", str(cert_path))
    monkeypatch.setenv("ACCOUNT_CLOSURE_IMAGE", "ghcr.io/fyberlabs/user-service@sha256:" + "a" * 64)
    return cert_path, key_path


async def test_real_tls_proxy_private_intake_and_denial_with_trust_failure(private, certificates, monkeypatch):
    _, private_app, subject, lookups, validated = private
    # The private fixture stubs native JWT validation and provider responses.
    # This replaces only its global HTTP factory so forwarding uses real TLS;
    # its already-open provider client remains an owned synthetic provider.
    monkeypatch.setattr(httpx, "AsyncClient", RealClient)
    config = closure_runtime.authority_config()
    config.app, config.host, config.lifespan = private_app, "127.0.0.1", "off"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.setblocking(False)
    port = listener.getsockname()[1]
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                    pytest.fail("private TLS listener did not start")
                await asyncio.sleep(0.01)
        monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_URL", f"https://127.0.0.1:{port}")
        public = FastAPI()
        public.include_router(closure_proxy.router, prefix="/api/v1")
        public.include_router(closure_proxy.read_router, prefix="/api/v1")
        async with RealClient(transport=httpx.ASGITransport(app=public), base_url="http://public") as client:
            reply = await client.post("/api/v1/me/account-closure", headers={"Authorization": "Bearer native-token"},
                                      json={"confirmation": "CLOSE MY ACCOUNT"})
            assert reply.status_code == 202 and reply.json()["subject"] == subject
            assert validated == ["native-token"] and len(lookups) == 2
            async def read():
                return await client.post("/api/v1/internal/account-lifecycle/check", json={"subject": subject},
                    headers={"X-Account-Lifecycle-Token": "r" * 32})
            assert await closure_health.check() is True
            result = await read()
            assert result.status_code == 200 and result.json() == {"blocked": True}
            monkeypatch.delenv("ACCOUNT_CLOSURE_AUTHORITY_CA_FILE")
            assert await closure_health.check() is False
            assert (await read()).status_code == 503  # No trust in the ephemeral self-signed CA.
            monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_CA_FILE", str(certificates[0]))
            monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_URL", f"https://localhost:{port}")
            assert (await read()).status_code == 503  # Correct CA, wrong certificate hostname.
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()


def test_explicit_trust_keeps_certificate_and_hostname_verification(certificates):
    context = authority_verify()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("failure", ["missing_key", "world_readable", "symlink", "invalid_cert", "tagged_image"])
def test_invalid_tls_or_image_cannot_start_listener(certificates, monkeypatch, failure, tmp_path):
    cert, key = certificates
    if failure == "missing_key":
        key.unlink()
    elif failure == "world_readable":
        key.chmod(0o644)
    elif failure == "symlink":
        link = tmp_path / "linked-key"
        link.symlink_to(key)
        monkeypatch.setenv("ACCOUNT_CLOSURE_TLS_KEY_FILE", str(link))
    elif failure == "invalid_cert":
        cert.write_text("invalid")
    else:
        monkeypatch.setenv("ACCOUNT_CLOSURE_IMAGE", "ghcr.io/fyberlabs/user-service:test")
    with pytest.raises(WorkerUnavailable):
        closure_runtime.authority_config()


def test_unavailable_ca_is_a_sanitized_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_CA_FILE", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="certificate trust unavailable"):
        authority_verify()


async def test_private_operational_error_does_not_escape_into_response_or_logs(private, monkeypatch, caplog):
    from user_service import closure_actions
    client, _, _, _, _ = private
    def broken(request):
        raise RuntimeError("owned-fixture-private-database-secret")
    monkeypatch.setattr(closure_actions, "jobs", broken)
    reply = await client.post("/api/v1/me/account-closure", headers={"Authorization": "Bearer native-token"},
                              json={"confirmation": "CLOSE MY ACCOUNT"})
    assert reply.status_code == 503 and reply.headers["cache-control"] == "no-store"
    assert "owned-fixture-private-database-secret" not in reply.text + caplog.text


async def test_private_startup_failure_is_sanitized(monkeypatch):
    from asgi_lifespan import LifespanManager
    from user_service import closure_authority
    monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_WORKER_DATABASE_URL", "postgresql+asyncpg://fixture:unused@localhost/fixture")
    def broken(*args, **kwargs):
        raise RuntimeError("owned-fixture-private-startup-secret")
    monkeypatch.setattr(closure_authority, "create_async_engine", broken)
    with pytest.raises(WorkerUnavailable, match="Account closure worker unavailable"):
        async with LifespanManager(closure_authority.create_app()):
            pytest.fail("unavailable authority started")
