"""Bounded native owner inventory before personal identifiers are unlinked."""

from __future__ import annotations

from sqlalchemy.exc import DBAPIError


class FinancialInventory:
    OWNERS = ("billing", "payment", "hypermesh")
    BATCH_SIZE = 100
    MAX_NONEMPTY_BATCHES = 20

    def __init__(self, jobs):
        self.jobs = jobs

    async def prepare(self, work):
        try:
            if await self.jobs.financial_inventory_ready(work):
                return True
            batches = 0
            for tenant in (None, *self.jobs.completed_tenants(work)):
                for owner in self.OWNERS:
                    while True:
                        if batches >= self.MAX_NONEMPTY_BATCHES:
                            return False
                        await self.jobs.heartbeat(work)
                        receipt = await self.jobs.prime_financial_inventory(
                            work, tenant, owner, limit=self.BATCH_SIZE
                        )
                        # Replayed empty/completed scopes must not consume the
                        # work budget and starve later scopes on every retry.
                        if receipt["processed"] > 0:
                            batches += 1
                        if receipt["complete"]:
                            break
                        if receipt["processed"] == 0:
                            return False
            return await self.jobs.financial_inventory_ready(work)
        except (DBAPIError, ValueError):
            return False
