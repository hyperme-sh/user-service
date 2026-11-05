"""Request an IdP-owned, expiring password action for an exact bound subject.

Keycloak creates and sends the action token. This service never handles its
value, chooses a recipient, or accepts a caller-controlled redirect/action.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
from urllib.parse import quote, urlparse

import httpx
from controlplane_api.config import settings
from controlplane_identity.account_lifecycle import service_secret, service_url

from user_service.closure_directory import DirectoryUnavailable, identity_url, native_response

RESET_LIFESPAN_SECONDS = 600


class PasswordResetUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("password_reset_unavailable")


class PasswordResetTargetMismatch(RuntimeError):
    def __init__(self):
        super().__init__("password_reset_identity_mismatch")


def tls_context(name: str):
    try:
        path = os.environ.get(name)
        return ssl.create_default_context(cafile=path) if path else True
    except Exception:
        raise PasswordResetUnavailable() from None


def endpoint(name: str) -> str:
    value = service_url(name)
    parsed = urlparse(value)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise PasswordResetUnavailable()
    return value


def operations_secret() -> str:
    try:
        value = service_secret("PASSWORD_RESET_OPERATIONS_TOKEN")
        if (len(value) > 512 or value == getattr(settings, "api_key_exchange_jwt_secret", None)
                or any(value == os.environ.get(name) for name in (
            "PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET", "ACCOUNT_CLOSURE_OPERATIONS_TOKEN",
            "ACCOUNT_CLOSURE_GUARD_TOKEN", "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET",
            "ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "KEYCLOAK_CLIENT_SECRET",
        ))):
            raise PasswordResetUnavailable()
        return value
    except RuntimeError:
        raise PasswordResetUnavailable() from None


class PasswordResetAuthorityClient:
    """Public process capability: request one fixed action, never load IdP admin secrets."""
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        try:
            if client.trust_env or os.environ.get("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET"):
                raise PasswordResetUnavailable()
            self.base = endpoint("PASSWORD_RESET_AUTHORITY_URL")
            self.secret = operations_secret()
        except RuntimeError:
            raise PasswordResetUnavailable() from None

    async def send(self, *, tenant_id, user_id, email: str, authorization: str) -> None:
        try:
            async with asyncio.timeout(12):
                async with self.client.stream(
                    "POST", self.base + "/internal/password-reset", follow_redirects=False,
                    headers={"X-Password-Reset-Token": self.secret, "Accept-Encoding": "identity",
                             "Authorization": authorization, "X-Tenant-ID": str(tenant_id)},
                    json={"tenant_id": str(tenant_id), "user_id": str(user_id), "email": email},
                ) as response:
                    if response.headers.get("Content-Encoding", "").lower() not in {"", "identity"}:
                        raise PasswordResetUnavailable()
                    raw = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        if len(raw) + len(chunk) > 32768:
                            raise PasswordResetUnavailable()
                        raw.extend(chunk)
                    status, result = response.status_code, json.loads(raw)
            if status in {404, 409}:
                raise PasswordResetTargetMismatch()
            if (status != 200 or not isinstance(result, dict)
                    or set(result) != {"sent"} or result["sent"] is not True):
                raise PasswordResetUnavailable()
        except (httpx.HTTPError, TimeoutError, ValueError):
            raise PasswordResetUnavailable() from None


class KeycloakPasswordResetClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        try:
            self.base = endpoint("PASSWORD_RESET_KEYCLOAK_URL")
            realm = os.environ.get("PASSWORD_RESET_KEYCLOAK_REALM", "")
            self.client_id = os.environ.get("PASSWORD_RESET_KEYCLOAK_CLIENT_ID", "")
            if (not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", realm)
                    or self.client_id != "operator-password-reset" or client.trust_env):
                raise PasswordResetUnavailable()
            self.realm = quote(realm, safe="")
            if (settings.keycloak_issuer or "").rstrip("/") != f"{self.base}/realms/{self.realm}":
                raise PasswordResetUnavailable()
            self.secret = service_secret("PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET")
            if (len(self.secret) > 512 or self.secret == getattr(settings, "api_key_exchange_jwt_secret", None)
                    or any(self.secret == os.environ.get(name) for name in (
                "PASSWORD_RESET_OPERATIONS_TOKEN", "KEYCLOAK_CLIENT_SECRET", "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET",
                "ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "ACCOUNT_CLOSURE_GUARD_TOKEN",
                "ACCOUNT_CLOSURE_OPERATIONS_TOKEN",
            ))):
                raise PasswordResetUnavailable()
        except RuntimeError:
            raise PasswordResetUnavailable() from None

    async def send(self, *, subject: str, email: str) -> None:
        try:
            async with asyncio.timeout(10):
                status, token = await native_response(
                    self.client, "POST",
                    f"{self.base}/realms/{self.realm}/protocol/openid-connect/token",
                    data={"grant_type": "client_credentials", "client_id": self.client_id,
                          "client_secret": self.secret},
                )
                value = token.get("access_token") if status == 200 and isinstance(token, dict) else None
                if (not isinstance(value, str) or not value or len(value) > 16384
                        or not value.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in value)):
                    raise PasswordResetUnavailable()
                url = identity_url(self.base, self.realm, subject)
                headers = {"Authorization": "Bearer " + value}
                status, user = await native_response(self.client, "GET", url, headers=headers)
                if status == 404:
                    raise PasswordResetTargetMismatch()
                if status != 200 or not isinstance(user, dict):
                    raise PasswordResetUnavailable()
                if (user.get("id") != subject or user.get("enabled") is not True
                        or not isinstance(user.get("email"), str)
                        or not isinstance(user.get("username"), str)
                        or user["username"].casefold().startswith("service-account-")
                        or user["email"].strip().casefold() != email.strip().casefold()
                        or "serviceAccountClientId" in user
                        or user.get("federationLink") is not None
                        or user.get("federatedIdentities") not in (None, [])):
                    raise PasswordResetTargetMismatch()
                status, credentials = await native_response(self.client, "GET", url + "/credentials", headers=headers)
                if status != 200 or not isinstance(credentials, list):
                    raise PasswordResetUnavailable()
                # Reset an existing local password; never create a new login
                # method for a passwordless or machine identity.
                if not any(isinstance(item, dict) and item.get("type") == "password" for item in credentials):
                    raise PasswordResetTargetMismatch()
                status, _ = await native_response(
                    self.client, "PUT", url + "/execute-actions-email", headers=headers,
                    params={"lifespan": RESET_LIFESPAN_SECONDS}, json=["UPDATE_PASSWORD"],
                )
                if status != 204:
                    raise PasswordResetUnavailable()
        except (DirectoryUnavailable, httpx.HTTPError, TimeoutError):
            raise PasswordResetUnavailable() from None
