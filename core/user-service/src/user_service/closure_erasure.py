"""Personal owner erasure after verified closure; financial work is separate."""

from __future__ import annotations

import uuid

from sqlalchemy.exc import DBAPIError

from user_service.closure_clients import OwnerUnavailable
from user_service.closure_idp import IdentityEffectUnavailable
from user_service.closure_inventory import FinancialInventory


class PersonalErasure:
    def __init__(self, jobs, identity, owners):
        self.jobs, self.identity, self.owners = jobs, identity, owners

    async def erase(self, work):
        # Check before even constructing an external deletion request. Holds on
        # financial records do not extend unrelated personal-data retention.
        work = await self.jobs.start_erasure(work)
        if not await FinancialInventory(self.jobs).prepare(work):
            await self.jobs.release(work, error="owner_unavailable")
            return None
        failed = False
        from user_service.verification_erasure import erase_verification
        if work.effects.get("verification_erasure", {}).get("complete") is not True:
            try:
                receipt = await erase_verification(work.subject)
                if receipt.get("complete") is True:
                    work = await self.jobs.effect(work, "verification_erasure", receipt)
            except OwnerUnavailable:
                failed = True
        try:
            await self.jobs.purge_profile(work)
        except (ValueError, DBAPIError):
            failed = True
        tenants = self.jobs.completed_tenants(work)
        for tenant in tenants:
            scope = await self.jobs.scope_view(work, tenant)
            if scope is None:
                # A missing original scope is not proof of an empty owner.
                failed = True
                continue
            try:
                await self.jobs.purge_profile(work, tenant)
            except (ValueError, DBAPIError):
                failed = True
            if "key_erasure" not in scope["effects"]:
                try:
                    receipt = await self.owners.purge_keys(work, tenant)
                    await self.jobs.scope_effect(work, tenant, "key_erasure", receipt)
                except OwnerUnavailable:
                    failed = True
            for gateway in scope["effects"].get("gateway_roster", []):
                name = "gateway_erasure:" + gateway
                if name in scope["effects"]:
                    continue
                original = scope["effects"].get("gateway:" + gateway)
                if not isinstance(original, dict) or original.get("closed") is not True:
                    failed = True
                    continue
                if original.get("personal_data") is False:
                    # Original complete discovery proved there was no owner data;
                    # local retirement fenced later capture. Do not create a row.
                    await self.jobs.scope_effect(
                        work, tenant, name, {"not_present": True}
                    )
                    continue
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.owners.gateway(
                        work, tenant, uuid.UUID(gateway), "purge-owner"
                    )
                    await self.jobs.scope_effect(work, tenant, name, receipt)
                except OwnerUnavailable:
                    failed = True
        for tenant in tenants:
            scope = await self.jobs.scope_view(work, tenant)
            if scope is None or "model_erasure" in scope["effects"]:
                continue
            expected = scope["effects"].get("hypermesh", {}).get("model_ids")
            if not isinstance(expected, list):
                failed = True
                continue
            after, seen = None, set()
            while True:
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.owners.purge_models(work, tenant, after=after)
                    if receipt["complete"]:
                        # Empty current metadata alone is not physical cleanup
                        # proof. Every original revision must have contributed
                        # to the owner's atomically committed cleanup count.
                        if receipt["revisions"] != len(expected):
                            failed = True
                        else:
                            await self.jobs.scope_effect(
                                work, tenant, "model_erasure", receipt
                            )
                        break
                    next_after = receipt["next_after"]
                    if not receipt["more"]:
                        failed = True
                        break
                    if next_after in seen or (
                        after is not None and uuid.UUID(next_after) <= uuid.UUID(after)
                    ):
                        raise OwnerUnavailable()
                    seen.add(next_after)
                    if len(seen) >= max(len(expected), 1):
                        raise OwnerUnavailable()
                    after = next_after
                except OwnerUnavailable:
                    failed = True
                    break
        for tenant in (None, *tenants):
            for _ in range(20):
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.jobs.erase_host_associations(work, tenant)
                except (ValueError, DBAPIError):
                    failed = True
                    break
                if receipt["complete"]:
                    break
            else:
                failed = True
        for tenant in (None, *tenants):
            for _ in range(20):
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.jobs.erase_device_reviewers(work, tenant)
                except (ValueError, DBAPIError):
                    failed = True
                    break
                if receipt["complete"]:
                    break
            else:
                failed = True
        for tenant in (None, *tenants):
            for _ in range(20):
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.jobs.erase_payment_access(work, tenant)
                except (ValueError, DBAPIError):
                    failed = True
                    break
                if receipt["complete"]:
                    break
            else:
                failed = True
        for tenant in (None, *tenants):
            for _ in range(20):
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.jobs.erase_company_creators(work, tenant)
                except (ValueError, DBAPIError):
                    failed = True
                    break
                if receipt["complete"]:
                    break
            else:
                failed = True
        for tenant in (None, *tenants):
            for _ in range(20):
                await self.jobs.heartbeat(work)
                try:
                    receipt = await self.jobs.erase_runtime_credentials(work, tenant)
                except (ValueError, DBAPIError):
                    failed = True
                    break
                if receipt["complete"]:
                    break
                if receipt["processed"] == 0:
                    # Active or unexpired work must finish normally. Do not
                    # spin or mark this owner's remaining credentials erased.
                    failed = True
                    break
            else:
                failed = True
        try:
            work = await self.jobs.profiles_erased(work)
        except ValueError:
            failed = True
        if work.effects.get("identity_erasure", {}).get("complete") is not True:
            try:
                await self.identity.delete(
                    work.subject,
                    disable_receipt=work.effects.get("identity", {}).get("disabled")
                    is True,
                )
                work = await self.jobs.effect(
                    work, "identity_erasure", {"complete": True}
                )
            except IdentityEffectUnavailable:
                failed = True
        if not failed:
            work = await self.jobs.effect(work, "personal_owners_erased", True)
        # Never mark the whole account deleted here: remaining nonfinancial
        # owners and financial records need their own completion evidence.
        await self.jobs.release(
            work, error="owner_unavailable" if failed else "deadline_pending"
        )
        return work if not failed else None
