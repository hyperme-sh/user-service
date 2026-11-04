"""Retryable closure admission effects, with no transaction across network I/O.

The private bounded worker composes admission and personal owner stages.
Financial expiry and deployment acceptance remain separate prerequisites.
"""

from __future__ import annotations

from user_service.closure_clients import OwnerUnavailable
from user_service.closure_idp import IdentityEffectUnavailable
from user_service.closure_jobs import ClosureClaimLost


class ClosureProcessor:
    def __init__(self, jobs, identity, owners):
        self.jobs, self.identity, self.owners = jobs, identity, owners

    async def close(self, work):
        """Return after a durable pending retry or verified admission closure."""
        if work.state != "closing":
            raise ValueError("Admission closure requires a closing job")
        try:
            if work.effects.get("identity", {}).get("disabled") is not True:
                await self.identity.disable(work.subject)
                work = await self.jobs.identity_disabled(work)
            work = await self.jobs.prepare_platform_profile(work)
            tenants = await self.jobs.tenants(work)
            failed = False
            try:
                key_tenants = await self.owners.key_tenants(work)
                if not set(key_tenants).issubset(tenants):
                    raise OwnerUnavailable()
            except OwnerUnavailable:
                # Still revoke the registry's other keys and native admission.
                failed = True

            # Every tenant's credential authority is handled before any gateway
            # network call, including inactive tenants and accounts with no membership.
            for tenant in tenants:
                await self.jobs.prepare_scope(work, tenant)
                scope = await self.jobs.scope_view(work, tenant)
                if "api_keys" not in scope["effects"]:
                    try:
                        receipt = await self.owners.close_keys(work, tenant)
                        await self.jobs.scope_effect(work, tenant, "api_keys", receipt)
                    except OwnerUnavailable:
                        failed = True

            for tenant in tenants:
                scope = await self.jobs.scope_view(work, tenant)
                if "api_keys" not in scope["effects"]:
                    continue
                if "hypermesh" not in scope["effects"]:
                    try:
                        receipt = await self.owners.close_hypermesh(work, tenant)
                        await self.jobs.scope_effect(work, tenant, "hypermesh", receipt)
                    except OwnerUnavailable:
                        failed = True

            # Receiver failure does not roll back or prevent other native owners.
            for tenant in tenants:
                scope = await self.jobs.scope_view(work, tenant)
                if "hypermesh" not in scope["effects"]:
                    continue
                try:
                    current = await self.owners.gateways(tenant)
                    receivers = await self.jobs.remember_gateways(work, tenant, current)
                except OwnerUnavailable:
                    failed = True
                    continue
                keys = scope["effects"]["api_keys"]["keys"]
                grants = {
                    "key_ids": [key["id"] for key in keys],
                    "fingerprints": sorted(
                        {key["fingerprint"] for key in keys if key.get("fingerprint")}
                    ),
                    "lease_ids": scope["effects"]["hypermesh"]["lease_ids"],
                }
                for gateway in receivers:
                    name = "gateway:" + str(gateway)
                    if scope["effects"].get(name, {}).get("closed") is True:
                        continue
                    await self.jobs.heartbeat(work)
                    try:
                        await self.owners.gateway(
                            work, tenant, gateway, "deny-principal"
                        )
                        await self.owners.gateway(
                            work, tenant, gateway, "deny-grants", **grants
                        )
                        inventory = await self.owners.gateway(
                            work, tenant, gateway, "owner-inventory"
                        )
                        if inventory["has_resources"]:
                            await self.owners.gateway(
                                work, tenant, gateway, "close-owner", **grants
                            )
                        await self.jobs.scope_effect(
                            work,
                            tenant,
                            name,
                            {
                                "closed": True,
                                "personal_data": inventory["has_resources"],
                                **(
                                    {"capabilities": inventory["capabilities"]}
                                    if "capabilities" in inventory
                                    else {}
                                ),
                            },
                        )
                    except OwnerUnavailable:
                        failed = True
                # A newly registered receiver cannot disappear between scans.
                try:
                    latest = await self.owners.gateways(tenant)
                    remembered = await self.jobs.remember_gateways(work, tenant, latest)
                    if set(remembered) != set(receivers):
                        failed = True
                except OwnerUnavailable:
                    failed = True

            if failed:
                await self.jobs.release(work, error="owner_unavailable")
                return None
            return await self.jobs.mark_closed(work, tenants)
        except IdentityEffectUnavailable:
            await self.jobs.release(work, error="identity_unavailable")
            return None
        except ValueError:
            await self.jobs.release(work, error="owner_conflict")
            return None
        except ClosureClaimLost:
            # A replacement worker owns the job; do not write even an error.
            raise
