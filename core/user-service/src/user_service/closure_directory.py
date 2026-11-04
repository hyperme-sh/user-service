"""Read-only native target preflight; public services never load worker credentials."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from controlplane_api.config import settings
from controlplane_identity.account_lifecycle import service_secret, service_url


class DirectoryUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("native_identity_directory_unavailable")


class DirectoryNotFound(RuntimeError):
    def __init__(self):
        super().__init__("native_identity_not_found")


class ProtectedIdentity(RuntimeError):
    def __init__(self):
        super().__init__("protected_native_identity")


@dataclass(frozen=True)
class DirectoryIdentity:
    subject: str
    enabled: bool


def identity_record(value, subject: str) -> DirectoryIdentity:
    if not isinstance(value, dict) or value.get("id") != subject or type(value.get("enabled")) is not bool:
        raise DirectoryUnavailable()
    attributes = value.get("attributes")
    if attributes is None:
        attributes = {}
    if not isinstance(attributes, dict):
        raise DirectoryUnavailable()
    # This managed field is administrator-only. Malformed/noncanonical marker
    # values must not turn a protected principal into a customer deletion target.
    if "account_closure_protected" in attributes:
        raise ProtectedIdentity()
    return DirectoryIdentity(subject, value["enabled"])


def identity_url(base: str, realm: str, subject: str) -> str:
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512 or subject in {".", ".."}:
        raise DirectoryUnavailable()
    return f"{base}/admin/realms/{realm}/users/{quote(subject, safe='')}"


async def native_response(
    client: httpx.AsyncClient, method: str, url: str, *, max_bytes: int = 1024 * 1024, **kwargs
):
    """Bound the whole response, including slow streams, and suppress raw errors."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024:
        raise DirectoryUnavailable()
    try:
        headers = {**kwargs.pop("headers", {}), "Accept-Encoding": "identity"}
        async with asyncio.timeout(3):
            async with client.stream(method, url, headers=headers, follow_redirects=False, **kwargs) as response:
                if response.headers.get("Content-Encoding", "").lower() not in {"", "identity"}:
                    raise DirectoryUnavailable()
                body = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if len(body) + len(chunk) > max_bytes:
                        raise DirectoryUnavailable()
                    body.extend(chunk)
                value = json.loads(body) if body else None
                return response.status_code, value
    except (httpx.HTTPError, TimeoutError, ValueError):
        raise DirectoryUnavailable() from None


class KeycloakClosureReader:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.base = service_url("ACCOUNT_CLOSURE_KEYCLOAK_URL")
        realm = os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_REALM", "")
        if not realm or client.trust_env:
            raise DirectoryUnavailable()
        self.realm = quote(realm, safe="")
        self.client_id = os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_READER_CLIENT_ID", "account-closure-reader")
        if self.client_id != "account-closure-reader" or (settings.keycloak_issuer or "").rstrip("/") != f"{self.base}/realms/{self.realm}":
            raise DirectoryUnavailable()
        # A public request process must not receive the privileged worker secret.
        if "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET" in os.environ:
            raise DirectoryUnavailable()
        self.secret = service_secret("ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET")
        if len(self.secret) > 512 or any(self.secret == os.environ.get(name) for name in (
            "ACCOUNT_CLOSURE_GUARD_TOKEN", "ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "KEYCLOAK_CLIENT_SECRET",
        )):
            raise DirectoryUnavailable()

    async def lookup(self, subject: str) -> DirectoryIdentity:
        url = identity_url(self.base, self.realm, subject)
        status, response = await native_response(
            self.client, "POST", f"{self.base}/realms/{self.realm}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.secret},
        )
        token = response.get("access_token") if status == 200 and isinstance(response, dict) else None
        if not isinstance(token, str) or not token or len(token) > 16384 or not token.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in token):
            raise DirectoryUnavailable()
        status, response = await native_response(self.client, "GET", url, headers={"Authorization": "Bearer " + token})
        if status == 404:
            raise DirectoryNotFound()
        if status != 200:
            raise DirectoryUnavailable()
        return identity_record(response, subject)
