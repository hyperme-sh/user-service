"""Exact-subject Keycloak lifecycle effects; never search by email.

Retries always read the same user ID. An acknowledged disable is recorded by the
caller before profile deletion is permitted. No access token or user payload is
included in exceptions.
"""

from __future__ import annotations

import os
from urllib.parse import quote

import httpx
from controlplane_api.config import settings
from controlplane_identity.account_lifecycle import service_secret, service_url

from user_service.closure_directory import (
    DirectoryNotFound,
    DirectoryUnavailable,
    ProtectedIdentity,
    identity_record,
    identity_url,
    native_response,
)


class IdentityEffectUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("identity_effect_unavailable")


class KeycloakClosureClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.base = service_url("ACCOUNT_CLOSURE_KEYCLOAK_URL")
        realm = os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_REALM", "")
        self.client_id = os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_ID", "")
        if not realm or self.client_id != "account-closure-worker" or client.trust_env:
            raise IdentityEffectUnavailable()
        self.realm = quote(realm, safe="")
        if (settings.keycloak_issuer or "").rstrip(
            "/"
        ) != f"{self.base}/realms/{self.realm}":
            raise IdentityEffectUnavailable()
        self.secret = service_secret("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET")
        if len(self.secret) > 512 or any(self.secret == os.environ.get(name) for name in (
            "ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "ACCOUNT_CLOSURE_GUARD_TOKEN",
            "ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "KEYCLOAK_CLIENT_SECRET",
        )):
            raise IdentityEffectUnavailable()

    async def _token(self) -> str:
        status, response = await native_response(
            self.client, "POST",
            f"{self.base}/realms/{self.realm}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.secret},
        )
        value = response.get("access_token") if status == 200 and isinstance(response, dict) else None
        if (not isinstance(value, str) or not value or len(value) > 16384
                or not value.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in value)):
            raise IdentityEffectUnavailable()
        return value

    async def lookup(self, subject: str):
        """Read an exact target using the private worker credential before intake."""
        try:
            status, current = await native_response(
                self.client, "GET", identity_url(self.base, self.realm, subject),
                headers={"Authorization": f"Bearer {await self._token()}"},
            )
            if status == 404:
                raise DirectoryNotFound()
            if status != 200:
                raise DirectoryUnavailable()
            return identity_record(current, subject)
        except IdentityEffectUnavailable:
            raise DirectoryUnavailable() from None

    async def disable(self, subject: str) -> None:
        """Check protection, disable and log out, then verify the exact identity."""
        try:
            url = identity_url(self.base, self.realm, subject)
            headers = {"Authorization": f"Bearer {await self._token()}"}
            status, current = await native_response(self.client, "GET", url, headers=headers)
            if status != 200:
                raise IdentityEffectUnavailable()
            identity_record(current, subject)
            status, _ = await native_response(self.client, "PUT", url, json={"enabled": False}, headers=headers)
            if status != 204:
                raise IdentityEffectUnavailable()
            status, _ = await native_response(self.client, "POST", url + "/logout", headers=headers)
            if status != 204:
                raise IdentityEffectUnavailable()
            status, current = await native_response(self.client, "GET", url, headers=headers)
            if status != 200 or identity_record(current, subject).enabled:
                raise IdentityEffectUnavailable()
        except (DirectoryUnavailable, ProtectedIdentity, IdentityEffectUnavailable):
            raise IdentityEffectUnavailable() from None

    async def delete(self, subject: str, *, disable_receipt: bool) -> None:
        """Only a durable prior disable receipt permits a missing-user retry."""
        if disable_receipt is not True:
            raise IdentityEffectUnavailable()
        try:
            url = identity_url(self.base, self.realm, subject)
            headers = {"Authorization": f"Bearer {await self._token()}"}
            status, current = await native_response(self.client, "GET", url, headers=headers)
            if status == 404:
                return
            if status != 200 or identity_record(current, subject).enabled:
                raise IdentityEffectUnavailable()
            status, _ = await native_response(self.client, "DELETE", url, headers=headers)
            if status not in {204, 404}:
                raise IdentityEffectUnavailable()
            status, _ = await native_response(self.client, "GET", url, headers=headers)
            if status != 404:
                raise IdentityEffectUnavailable()
        except (DirectoryUnavailable, ProtectedIdentity, IdentityEffectUnavailable):
            raise IdentityEffectUnavailable() from None
