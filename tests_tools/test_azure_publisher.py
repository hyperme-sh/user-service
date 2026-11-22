"""Exercise the publisher's registry exchange and protection with local command fixtures."""

import os
from pathlib import Path
import subprocess
import sys
from textwrap import dedent

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/publish-azure-runtime.yml"
MOCK = r'''
import json
import os
from pathlib import Path
import sys

command = Path(sys.argv[0]).name
args = sys.argv[1:]
server = "acrfybercg47.azurecr.io"
endpoint = f"https://{server}"
repository = "user-service"
digest = os.environ["DIGEST"]

if command == "az":
    assert args == ["account", "get-access-token", "--resource", "https://containerregistry.azure.net",
                    "--query", "accessToken", "-o", "tsv"], args
    print("test-azure-token")
elif command == "docker":
    if args[:1] == ["login"]:
        assert args[1] in {"ghcr.io", server}, args
        assert args[-1] == "--password-stdin", args
        expected = "test-gh-token" if args[1] == "ghcr.io" else "test-refresh"
        assert sys.stdin.read() == expected
    elif args[:2] == ["manifest", "inspect"]:
        assert args[2] == f"{server}/{repository}:v1.2.3"
    else:
        assert args[:3] == ["buildx", "imagetools", "inspect"], args
        print(json.dumps({"digest": digest}))
else:
    assert command == "curl" and args[:4] == ["--disable", "-fsS", "--max-time", "30"], args
    body = sys.stdin.read()
    request = args[4:]
    if request[0] == endpoint + "/oauth2/exchange":
        assert body == "test-azure-token"
        assert request[1:] == [
            "--data", "grant_type=access_token", "--data-urlencode", "tenant=test-tenant",
            "--data-urlencode", f"service={server}", "--data-urlencode", "access_token@-",
        ]
        print(json.dumps({"refresh_token": "test-refresh"}))
    elif request[0] == endpoint + "/oauth2/token":
        assert body == "test-refresh"
        assert request[1:] == [
            "--data", "grant_type=refresh_token", "--data-urlencode", f"service={server}",
            "--data-urlencode", f"scope=repository:{repository}:metadata_read,metadata_write",
            "--data-urlencode", "refresh_token@-",
        ]
        print(json.dumps({"access_token": "test-metadata"}))
    else:
        assert request[:2] == ["--config", "-"]
        assert body == 'header = "Authorization: Bearer test-metadata"\n'
        tag_url = f"{endpoint}/acr/v1/{repository}/_tags/v1.2.3?api-version=2021-07-01"
        manifest_url = f"{endpoint}/acr/v1/{repository}/_manifests/{digest}?api-version=2021-07-01"
        url, *options = request[2:]
        assert url in {tag_url, manifest_url}, url
        kind = "tag" if url == tag_url else "manifest"
        with open(os.environ["REQUESTS"], "a") as log:
            print(f"{'PATCH' if options else 'GET'} {kind}", file=log)
        if options:
            assert options[:5] == ["--request", "PATCH", "--header", "Content-Type: application/json",
                                   "--data"], options
            fields = {"deleteEnabled": False}
            if kind == "tag":
                fields["writeEnabled"] = False
            assert json.loads(options[5]) == fields
        else:
            print(json.dumps({kind: {"digest": digest, "changeableAttributes": {
                "readEnabled": True, "deleteEnabled": os.environ["UNPROTECTED"] == kind,
                "writeEnabled": False,
            }}}))
'''


@pytest.mark.parametrize("unprotected", ["", "tag", "manifest"])
def test_publisher_requires_verified_registry_protection(tmp_path, unprotected):
    step = WORKFLOW.read_text().split(
        "- name: Copy the qualified image without rebuilding and protect the tag", 1
    )[1]
    script = dedent(step.split("run: |\n", 1)[1].split("\n      - name:", 1)[0])
    for command in ("az", "docker", "curl"):
        fixture = tmp_path / command
        fixture.write_text(f"#!{sys.executable}\n{MOCK}")
        fixture.chmod(0o700)
    requests = tmp_path / "requests"
    summary = tmp_path / "summary"
    env = {
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path),
        "REQUESTS": str(requests),
        "GITHUB_STEP_SUMMARY": str(summary),
        "DIGEST": "sha256:" + "a" * 64,
        "VERSION_TAG": "v1.2.3",
        "ACR_TENANT": "test-tenant",
        "GH_TOKEN": "test-gh-token",
        "GITHUB_ACTOR": "test-actor",
        "UNPROTECTED": unprotected,
    }

    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=10)

    expected = ["PATCH tag", "PATCH manifest", "GET tag"]
    if unprotected != "tag":
        expected.append("GET manifest")
    assert requests.read_text().splitlines() == expected, result.stderr
    assert result.returncode == (1 if unprotected else 0), result.stderr
    if unprotected:
        assert not summary.exists()
    else:
        assert "Protected acrfybercg47.azurecr.io/user-service:v1.2.3" in summary.read_text()
