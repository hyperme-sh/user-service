"""Bounded purpose-specific closure RPCs; replies are evidence, never authority."""

from __future__ import annotations

import json
import uuid

import httpx
from controlplane_identity.account_lifecycle import service_secret, service_url
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictInt

LIMIT = 100_000
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class OwnerUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("owner_unavailable")


class Receipt(BaseModel):
    model_config = ConfigDict(extra="ignore")


class KeyReceipt(Receipt):
    id: uuid.UUID
    fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    purpose: str = Field(min_length=1, max_length=64)


class GlobalKeyReceipt(KeyReceipt):
    tenant_id: uuid.UUID


class KeyInventory(Receipt):
    keys: list[KeyReceipt] = Field(max_length=LIMIT)


class GlobalKeys(Receipt):
    keys: list[GlobalKeyReceipt] = Field(max_length=LIMIT)


class HypermeshReceipt(Receipt):
    model_ids: list[uuid.UUID] = Field(max_length=LIMIT)
    lease_ids: list[uuid.UUID] = Field(max_length=LIMIT)
    device_ids: list[uuid.UUID] = Field(max_length=LIMIT)
    registration_ids: list[uuid.UUID] = Field(max_length=LIMIT)
    organization_ids: list[uuid.UUID] = Field(max_length=LIMIT)
    has_resources: StrictBool
    tickets_revoked: StrictBool
    new_selling_disabled: StrictBool
    model_closure_recorded: StrictBool
    model_closed_at: AwareDatetime | None = None


class Roster(Receipt):
    complete: StrictBool
    tenant_id: uuid.UUID
    gateway_ids: list[uuid.UUID] = Field(max_length=LIMIT)


class ErasureReceipt(Receipt):
    deleted: StrictInt = Field(ge=0)
    remaining: StrictInt = Field(ge=0, le=0)


class ModelErasureReceipt(Receipt):
    complete: StrictBool
    more: StrictBool
    next_after: uuid.UUID | None
    revisions: StrictInt = Field(ge=0)
    validations: StrictInt = Field(ge=0)
    lease_targets: StrictInt = Field(ge=0)
    completed_at: AwareDatetime | None


class ClosureOwners:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def call(self, service, path, *, body=None, tenant=None, gateway=None):
        """Only trusted configuration chooses destinations; never follow redirects."""
        try:
            name = (
                f"ACCOUNT_CLOSURE_GATEWAY_{gateway.hex.upper()}_URL"
                if gateway is not None
                else f"ACCOUNT_CLOSURE_{service}_URL"
            )
            headers = {
                "X-Account-Lifecycle-Token": service_secret(
                    "ACCOUNT_CLOSURE_OPERATIONS_TOKEN"
                )
            }
            if tenant is not None:
                headers["X-Tenant-ID"] = str(tenant)
            async with self.client.stream(
                "POST" if body is not None else "GET",
                service_url(name) + path,
                headers=headers,
                json=body,
                follow_redirects=False,
                timeout=5,
            ) as response:
                if response.status_code != 200:
                    raise OwnerUnavailable()
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > MAX_RESPONSE_BYTES:
                        raise OwnerUnavailable()
                value = json.loads(payload)
            if not isinstance(value, dict):
                raise OwnerUnavailable()
            return value
        except Exception:
            # Never persist request URLs, bearer secrets, payloads or contacts.
            raise OwnerUnavailable() from None

    @staticmethod
    def body(work):
        if work.closed_at is None:
            raise OwnerUnavailable()
        return {"subject": work.subject, "closed_at": work.closed_at.isoformat()}

    async def key_tenants(self, work):
        value = await self.call(
            "KEYS", "/api/v1/api-keys/internal/owner-inventory", body=self.body(work)
        )
        try:
            receipt = GlobalKeys.model_validate(value)
            keys = receipt.keys
            if len({key.id for key in keys}) != len(keys):
                raise OwnerUnavailable()
            return sorted({key.tenant_id for key in keys}, key=str)
        except Exception:
            raise OwnerUnavailable() from None

    async def close_keys(self, work, tenant):
        value = await self.call(
            "KEYS",
            "/api/v1/api-keys/internal/close-owner",
            body=self.body(work),
            tenant=tenant,
        )
        try:
            receipt = KeyInventory.model_validate(value)
            if len({key.id for key in receipt.keys}) != len(receipt.keys):
                raise OwnerUnavailable()
            return receipt.model_dump(mode="json")
        except Exception:
            raise OwnerUnavailable() from None

    async def purge_keys(self, work, tenant):
        value = await self.call(
            "KEYS",
            "/api/v1/api-keys/internal/purge-owner",
            body=self.body(work),
            tenant=tenant,
        )
        try:
            ErasureReceipt.model_validate(value)
            # A lost reply can make deleted=0 on retry; native remaining=0 is
            # the acknowledgement. Keep original target inventory separately.
            return {"remaining": 0}
        except Exception:
            raise OwnerUnavailable() from None

    async def close_hypermesh(self, work, tenant):
        value = await self.call(
            "HYPERMESH",
            "/api/v1/hypermesh/internal/account-lifecycle/close-owner",
            body=self.body(work),
            tenant=tenant,
        )
        try:
            receipt = HypermeshReceipt.model_validate(value)
            if (
                not receipt.tickets_revoked
                or not receipt.new_selling_disabled
                or receipt.model_closure_recorded != bool(receipt.model_ids)
                or (
                    bool(receipt.model_ids)
                    and (
                        receipt.model_closed_at is None
                        or receipt.model_closed_at > work.closed_at
                    )
                )
                or receipt.has_resources
                != any(
                    [
                        receipt.model_ids,
                        receipt.lease_ids,
                        receipt.device_ids,
                        receipt.registration_ids,
                        receipt.organization_ids,
                    ]
                )
            ):
                raise OwnerUnavailable()
            for field in (
                "model_ids",
                "lease_ids",
                "device_ids",
                "registration_ids",
                "organization_ids",
            ):
                ids = getattr(receipt, field)
                if len(set(ids)) != len(ids):
                    raise OwnerUnavailable()
            return receipt.model_dump(mode="json")
        except Exception:
            raise OwnerUnavailable() from None

    async def purge_models(self, work, tenant, *, after=None):
        path = "/api/v1/hypermesh/internal/account-lifecycle/purge-models"
        if after is not None:
            path += "?after=" + str(uuid.UUID(str(after)))
        value = await self.call("HYPERMESH", path, body=self.body(work), tenant=tenant)
        try:
            receipt = ModelErasureReceipt.model_validate(value)
            if receipt.more != (receipt.next_after is not None) or (
                receipt.complete and (receipt.more or receipt.completed_at is None)
            ):
                raise OwnerUnavailable()
            return receipt.model_dump(mode="json")
        except (ValueError, OwnerUnavailable):
            raise OwnerUnavailable() from None

    async def gateways(self, tenant):
        value = await self.call(
            "HYPERMESH",
            "/api/v1/hypermesh/internal/account-lifecycle/gateway-roster",
            tenant=tenant,
        )
        try:
            receipt = Roster.model_validate(value)
            if (
                receipt.complete is not True
                or receipt.tenant_id != tenant
                or len(set(receipt.gateway_ids)) != len(receipt.gateway_ids)
            ):
                raise OwnerUnavailable()
            return sorted(receipt.gateway_ids, key=str)
        except Exception:
            raise OwnerUnavailable() from None

    async def gateway(self, work, tenant, gateway, action, **extra):
        if action not in {
            "deny-principal",
            "deny-grants",
            "owner-inventory",
            "close-owner",
            "purge-owner",
        }:
            raise OwnerUnavailable()
        value = await self.call(
            None,
            f"/api/v1/internal/account-lifecycle/{action}",
            tenant=tenant,
            gateway=gateway,
            body={
                **extra,
                **self.body(work),
                "tenant_id": str(tenant),
                "expected_gateway_id": str(gateway),
            },
        )
        if value.get("gateway_id") != str(gateway):
            raise OwnerUnavailable()
        expected = {
            "deny-principal": ("denial_persisted",),
            "deny-grants": ("denial_persisted",),
            "close-owner": (
                "denial_persisted",
                "history_closure_recorded",
                "training_deleted",
            ),
            "purge-owner": ("erasure_complete",),
        }
        if any(value.get(field) is not True for field in expected.get(action, ())):
            raise OwnerUnavailable()
        if action == "owner-inventory":
            history, training = value.get("history"), value.get("training")
            if (
                not isinstance(history, dict)
                or not isinstance(training, dict)
                or type(history.get("present")) is not bool
                or type(training.get("present")) is not bool
                or type(value.get("has_resources")) is not bool
                or value["has_resources"] != (history["present"] or training["present"])
            ):
                raise OwnerUnavailable()
            # Counts/content are not needed for admission closure evidence.
            result = {"has_resources": value["has_resources"]}
            if "capabilities" in value:
                capabilities = value["capabilities"]
                if not isinstance(capabilities, dict) or set(capabilities) != {
                    "history",
                    "training",
                }:
                    raise OwnerUnavailable()
                for name, owner in (("history", history), ("training", training)):
                    mode = capabilities[name]
                    if (
                        not isinstance(mode, str)
                        or mode not in {"configured", "disabled"}
                        or (
                            mode == "disabled"
                            and (
                                owner.get("disabled") is not True
                                or owner["present"] is not False
                            )
                        )
                    ):
                        raise OwnerUnavailable()
                result["capabilities"] = capabilities
            return result
        if action == "purge-owner":
            try:
                history = ErasureReceipt.model_validate(value.get("history"))
                training = ErasureReceipt.model_validate(value.get("training"))
                return {
                    "erasure_complete": True,
                    "history": history.model_dump(),
                    "training": training.model_dump(),
                }
            except Exception:
                raise OwnerUnavailable() from None
        return {field: True for field in expected[action]}
