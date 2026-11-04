"""Resolve the opt-in overlay using synthetic files, without starting containers."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(params=[False, True], ids=["base", "vm"])
def compose(tmp_path, request):
    docker = shutil.which("docker")
    if not docker or subprocess.run([docker, "compose", "version"], capture_output=True, check=False).returncode:
        pytest.fail("Docker Compose CLI required for source-runtime validation")
    root = Path(os.environ["CLOSURE_RUNTIME_ROOT"]).resolve()
    empty = tmp_path / "empty.env"
    empty.write_text("")
    private = tmp_path / "private.env"
    private.write_text("ACCOUNT_CLOSURE_WORKER_DATABASE_URL=postgresql+asyncpg://worker:fixture@postgres/controlplane\n"
                       "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET=fixture-private-worker-secret\n")
    public = tmp_path / "public.env"
    public.write_text("ACCOUNT_CLOSURE_GUARD_TOKEN=fixture-read-only-token\n")
    certificate = tmp_path / "fixture-certificate"
    certificate.write_text("owned fixture; configuration validation only")
    environment = {"PATH": os.environ["PATH"],
        "ACCOUNT_CLOSURE_IMAGE": "ghcr.io/fyberlabs/user-service@sha256:" + "a" * 64,
        "ACCOUNT_CLOSURE_PRIVATE_ENV_FILE": str(private), "ACCOUNT_CLOSURE_PUBLIC_ENV_FILE": str(public),
        "ACCOUNT_CLOSURE_TLS_CERT_SOURCE": str(certificate), "ACCOUNT_CLOSURE_TLS_KEY_SOURCE": str(certificate),
        "ACCOUNT_CLOSURE_TLS_CA_SOURCE": str(certificate), "ACCOUNT_CLOSURE_AUTHORITY_HOST": "closure.example.test",
        "USER_SERVICE_DATABASE_URL": "postgresql+asyncpg://public:fixture@postgres/controlplane"}
    files = [root / "docker-compose.yaml"]
    if request.param:
        vm = root / "docker-compose.vm.yaml"
        files.append(vm)
        for name in re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", vm.read_text()):
            environment.setdefault(name, "owned-fixture-value")
    files.append(root / "compose.account-closure.yaml")
    command = [docker, "compose", "--env-file", str(empty), *(value for path in files for value in ("-f", str(path))),
               "--profile", "account-closure", "config"]
    return command, environment


def test_resolved_overlay_is_private_immutable_and_keeps_writer_secrets_out_of_public(compose):
    command, environment = compose
    subprocess.run([*command, "--quiet"], env=environment, capture_output=True, check=True)
    result = subprocess.run([*command, "--format", "json"], env=environment, capture_output=True, check=True)
    services = json.loads(result.stdout)["services"]
    authority, worker, public = [services[name] for name in ("account-closure-authority", "account-closure-worker", "user-service")]
    for private in (authority, worker):
        assert private["profiles"] == ["account-closure"] and not private.get("ports")
        assert private["image"] == environment["ACCOUNT_CLOSURE_IMAGE"]
        assert private["read_only"] and private["user"] == "65532:65532"
        assert private["cap_drop"] == ["ALL"] and "no-new-privileges:true" in private["security_opt"]
        assert private["environment"]["ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET"] == "fixture-private-worker-secret"
        assert private["environment"]["FASTAPI_ENV"] == "production"
        assert not private.get("build")
    assert authority["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert authority["depends_on"]["controlplane-migrate"]["condition"] == "service_completed_successfully"
    assert worker["depends_on"]["account-closure-authority"]["condition"] == "service_healthy"
    assert authority["healthcheck"]["test"][-1] == "user_service.closure_health"
    assert public["environment"]["DATABASE_URL"] == environment["USER_SERVICE_DATABASE_URL"]
    assert public["environment"]["ACCOUNT_CLOSURE_AUTHORITY_URL"] == "https://closure.example.test:8443"
    assert not any(name in public["environment"] for name in (
        "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", "ACCOUNT_CLOSURE_WORKER_DATABASE_URL"))
    assert [item["source"] for item in public["secrets"]] == ["closure_authority_ca"]
    assert "ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED" not in public["environment"]
    assert "ACCOUNT_CLOSURE_WORKER_ENABLED" not in worker["environment"]
