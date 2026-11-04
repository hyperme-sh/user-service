"""Durable closure intents and claims; callers perform network effects separately."""

from __future__ import annotations

import copy
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from controlplane_tenancy.account_profile import (
    _closure_retention,
    disable_subject_memberships,
)
from controlplane_tenancy.tenant_guc import set_current_tenant_id_guc
from controlplane_tenancy.tenant_membership import (
    identity_retired_at,
    lock_identity,
    retire_identity,
)
from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DBAPIError

from user_service.models import AccountLifecycle, AccountLifecycleScope


class ClosureClaimLost(RuntimeError):
    pass


@dataclass(frozen=True)
class ClosureWork:
    subject: str
    claim_id: uuid.UUID | None
    state: str
    closed_at: datetime | None
    effects: dict


def view(row):
    return ClosureWork(
        row.subject, row.claim_id, row.state, row.closed_at, copy.deepcopy(row.effects)
    )


def same_json(left, right) -> bool:
    """Structural JSON equality. Booleans are not numbers (`True` is not `1`)."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return False
        return all(same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            same_json(item, other) for item, other in zip(left, right)
        )
    return left == right


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ClosureJobs:
    def __init__(self, maker, *, clock=None):
        self.maker = maker
        self.clock = clock or (lambda: datetime.now(UTC))

    @asynccontextmanager
    async def transaction(self, tenant=None):
        async with self.maker.begin() as session:
            await session.execute(text("SET LOCAL lock_timeout='2000ms'"))
            await session.execute(text("SET LOCAL statement_timeout='10000ms'"))
            await set_current_tenant_id_guc(session, tenant)
            yield session

    async def _database_now(self, session) -> datetime:
        """Lifecycle, lease and retry instants share PostgreSQL's clock."""
        value = await session.scalar(text("SELECT transaction_timestamp()"))
        if not isinstance(value, datetime):
            raise RuntimeError("Database clock unavailable")  # noqa: TRY004 - database contract failure
        return _aware(value)

    async def request(self, subject, actor, source):
        """Trusted caller has verified the self subject or global operator role."""
        if any(
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 512
            or value.startswith("apikey:")
            for value in (subject, actor)
        ):
            raise ValueError("Exact account identities required")
        if source not in {"self_service", "operator"}:
            raise ValueError("Verified closure source required")
        async with self.transaction() as session:
            # Serialize requests with retirement and scope preparation before
            # reading provenance, including concurrent first requests.
            await lock_identity(session, subject)
            existing = await session.get(
                AccountLifecycle, subject, populate_existing=True
            )
            if existing is not None:
                if (
                    type(existing.effects.get("processor_version")) is not int
                    or existing.effects["processor_version"] != 1
                ):
                    raise ValueError("Legacy closure requires explicit reconciliation")
                return view(existing)
            if await identity_retired_at(session, subject) is not None:
                # Older retirement can have erased profile aliases without a
                # native inventory. Never manufacture an empty original scope.
                raise ValueError("Legacy closure requires explicit reconciliation")
            at = await self._database_now(session)
            await retire_identity(session, subject, at)
            await session.execute(
                insert(AccountLifecycle)
                .values(
                    subject=subject,
                    requested_at=at,
                    requested_by=actor,
                    source=source,
                    state="closing",
                    retry_at=await self._database_now(session),
                    financial_hold=False,
                    effects={"processor_version": 1},
                )
                .on_conflict_do_nothing(index_elements=["subject"])
            )
            row = await session.get(AccountLifecycle, subject, populate_existing=True)
            return view(row)

    async def claim(self, subject=None):
        async with self.transaction() as session:
            at = await self._database_now(session)
            stmt = (
                select(AccountLifecycle)
                .where(
                    AccountLifecycle.effects["processor_version"].astext == "1",
                    func.jsonb_typeof(AccountLifecycle.effects["processor_version"])
                    == "number",
                    or_(
                        AccountLifecycle.state != "deleted",
                        AccountLifecycle.financial_deleted_at.is_(None),
                    ),
                    AccountLifecycle.retry_at <= at,
                    or_(
                        AccountLifecycle.claim_until.is_(None),
                        AccountLifecycle.claim_until < at,
                    ),
                )
                .order_by(AccountLifecycle.retry_at, AccountLifecycle.subject)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if subject is not None:
                stmt = stmt.where(AccountLifecycle.subject == subject)
            row = await session.scalar(stmt)
            if row is None:
                return None
            row.claim_id = uuid.uuid4()
            row.claim_until = at + timedelta(seconds=60)
            await session.flush()
            return view(row)

    async def owned(self, session, work):
        row = await session.get(
            AccountLifecycle, work.subject, with_for_update=True, populate_existing=True
        )
        now = await self._database_now(session)
        if (
            row is None
            or work.claim_id is None
            or row.claim_id != work.claim_id
            or row.claim_until is None
            or _aware(row.claim_until) <= now
        ):
            raise ClosureClaimLost("Closure claim is no longer current")
        row.claim_until = now + timedelta(seconds=60)
        return row

    async def effect(self, work, name, receipt):
        async with self.transaction() as session:
            row = await self.owned(session, work)
            effects = copy.deepcopy(row.effects)
            if name in effects and not same_json(effects[name], receipt):
                raise ValueError("Original closure receipt cannot be replaced")
            effects[name] = copy.deepcopy(receipt)
            row.effects = effects
            return view(row)

    async def identity_disabled(self, work):
        """Only call after the native disable/logout/readback acknowledgement."""
        async with self.transaction() as session:
            row = await self.owned(session, work)
            if row.closed_at is None:
                row.closed_at = await self._database_now(session)
                row.effects = {**row.effects, "identity": {"disabled": True}}
            return view(row)

    async def prepare_scope(self, work, tenant):
        async with self.transaction(tenant) as session:
            # Match intent creation's lock order, before touching directory rows.
            await lock_identity(session, work.subject)
            row = await self.owned(session, work)
            if row.closed_at is None:
                raise ValueError("Verified identity disablement must be recorded first")
            if tenant is None:
                return await self._platform_scope(session, row)
            scope = await session.get(
                AccountLifecycleScope, (tenant, work.subject), with_for_update=True
            )
            if (
                scope is not None
                and scope.effects.get("profile_inventory_complete") is True
            ):
                return {
                    "user_ids": list(scope.user_ids),
                    "effects": copy.deepcopy(scope.effects),
                }
            if scope is not None and scope.user_ids:
                raise ValueError("Legacy scope inventory requires reconciliation")
            identifiers = await disable_subject_memberships(
                session, tenant, work.subject
            )
            if scope is None:
                scope = AccountLifecycleScope(
                    tenant_id=tenant, subject=work.subject, user_ids=[], effects={}
                )
                session.add(scope)
            scope.user_ids = [str(value) for value in identifiers]
            scope.effects = {**scope.effects, "profile_inventory_complete": True}
            await session.flush()
            return {
                "user_ids": list(scope.user_ids),
                "effects": copy.deepcopy(scope.effects),
            }

    async def scope_effect(self, work, tenant, name, receipt):
        async with self.transaction(tenant) as session:
            await self.owned(session, work)
            scope = await session.get(
                AccountLifecycleScope,
                (tenant, work.subject),
                with_for_update=True,
                populate_existing=True,
            )
            if (
                scope is None
                or scope.effects.get("profile_inventory_complete") is not True
            ):
                raise ValueError("Complete canonical scope inventory required")
            effects = copy.deepcopy(scope.effects)
            if name in effects and not same_json(effects[name], receipt):
                raise ValueError("Original owner receipt cannot be replaced")
            scope.effects = {**effects, name: copy.deepcopy(receipt)}

    async def _platform_scope(self, session, row):
        """Platform directory rows have no tenant key, so the lifecycle stores them."""
        saved = row.effects.get("platform_profile")
        if (
            isinstance(saved, dict)
            and saved.get("profile_inventory_complete") is True
            and isinstance(saved.get("user_ids"), list)
        ):
            return {
                "user_ids": list(saved["user_ids"]),
                "effects": {"profile_inventory_complete": True},
            }
        identifiers = await disable_subject_memberships(session, None, row.subject)
        receipt = {
            "user_ids": [str(value) for value in identifiers],
            "profile_inventory_complete": True,
        }
        row.effects = {**row.effects, "platform_profile": receipt}
        return {
            "user_ids": list(receipt["user_ids"]),
            "effects": {"profile_inventory_complete": True},
        }

    async def release(self, work, *, retry_at=None, error=None):
        if error is not None and error not in {
            "owner_unavailable",
            "identity_unavailable",
            "owner_conflict",
            "deadline_pending",
        }:
            raise ValueError("Only a sanitized closure error code may be recorded")
        async with self.transaction() as session:
            row = await self.owned(session, work)
            row.last_error = error
            # An explicit retry_at is the caller's schedule. The default backoff
            # uses the database clock. Neither one is a retention hold.
            row.retry_at = retry_at or await self._database_now(session) + timedelta(
                seconds=30
            )
            row.claim_id = row.claim_until = None

    async def tenants(self, work=None):
        """Include inactive tenants; a hidden or truncated registry is not empty."""
        from controlplane_tenancy.tenant_registry import tenant_ids_page

        identifiers = []
        after = None
        while True:
            async with self.transaction() as session:
                if work is not None:
                    await self.owned(session, work)
                page = await tenant_ids_page(session, after=after, limit=1000)
            identifiers.extend(page)
            if len(identifiers) > 100_000:
                raise ValueError("Closure tenant inventory exceeds limit")
            if len(page) < 1000:
                return identifiers
            after = page[-1]

    async def scope_view(self, work, tenant):
        async with self.transaction(tenant) as session:
            await self.owned(session, work)
            scope = await session.get(AccountLifecycleScope, (tenant, work.subject))
            if scope is None:
                return None
            return {
                "user_ids": list(scope.user_ids),
                "effects": copy.deepcopy(scope.effects),
            }

    async def prepare_platform_profile(self, work):
        async with self.transaction() as session:
            await lock_identity(session, work.subject)
            row = await self.owned(session, work)
            if row.closed_at is None:
                raise ValueError("Verified identity disablement required")
            if "platform_profile" not in row.effects:
                identifiers = await disable_subject_memberships(
                    session, None, work.subject
                )
                row.effects = {
                    **row.effects,
                    "platform_profile": {
                        "user_ids": [str(value) for value in identifiers]
                    },
                }
            return view(row)

    async def mark_closed(self, work, tenants):
        """Only committed complete owner receipts permit the closed transition."""
        # Check the current registry, not a worker-provided shortened tenant list.
        if list(tenants) != await self.tenants(work):
            raise ValueError("Tenant registry changed during closure")
        for tenant in tenants:
            scope = await self.scope_view(work, tenant)
            if scope is None:
                raise ValueError("Incomplete closure scope")
            effects = scope["effects"]
            if (
                effects.get("profile_inventory_complete") is not True
                or not isinstance(effects.get("api_keys", {}).get("keys"), list)
                or not isinstance(effects.get("hypermesh", {}).get("model_ids"), list)
                or effects.get("hypermesh", {}).get("tickets_revoked") is not True
                or effects.get("hypermesh", {}).get("new_selling_disabled") is not True
                or not isinstance(effects.get("gateway_roster"), list)
            ):
                raise ValueError("Incomplete native owner closure receipts")
            for gateway in effects["gateway_roster"]:
                uuid.UUID(gateway)
                if effects.get("gateway:" + gateway, {}).get("closed") is not True:
                    raise ValueError("Incomplete gateway closure receipts")
        async with self.transaction() as session:
            row = await self.owned(session, work)
            if (
                row.closed_at is None
                or row.effects.get("identity", {}).get("disabled") is not True
                or "platform_profile" not in row.effects
            ):
                raise ValueError("Verified global owner closure receipts required")
            frozen_tenants = [str(value) for value in tenants]
            if (
                "scope_tenants" in row.effects
                and row.effects["scope_tenants"] != frozen_tenants
            ):
                raise ValueError(
                    "Original completed scope inventory cannot be replaced"
                )
            row.effects = {
                **row.effects,
                "scope_discovery": True,
                "scope_tenants": frozen_tenants,
            }
            if row.state == "closing":
                row.state = "closed"
                row.retry_at = row.closed_at + _closure_retention()
                row.last_error = "deadline_pending"
                row.claim_id = row.claim_until = None
            return view(row)

    async def remember_gateways(self, work, tenant, identifiers):
        async with self.transaction(tenant) as session:
            await self.owned(session, work)
            scope = await session.get(
                AccountLifecycleScope,
                (tenant, work.subject),
                with_for_update=True,
                populate_existing=True,
            )
            if scope is None:
                raise ValueError("Canonical scope required")
            old = scope.effects.get("gateway_roster", [])
            combined = sorted(
                {str(uuid.UUID(value)) for value in [*old, *map(str, identifiers)]}
            )
            if len(combined) > 100_000:
                raise ValueError("Gateway closure inventory exceeds limit")
            scope.effects = {**scope.effects, "gateway_roster": combined}
            return [uuid.UUID(value) for value in combined]

    async def start_erasure(self, work):
        async with self.transaction() as session:
            row = await self.owned(session, work)
            if (
                row.state not in {"closed", "deleting"}
                or row.closed_at is None
                or await self._database_now(session)
                < row.closed_at + _closure_retention()
                or row.effects.get("scope_discovery") is not True
                or row.effects.get("identity", {}).get("disabled") is not True
            ):
                raise ValueError(
                    "Completed closure and personal retention boundary required"
                )
            self.completed_tenants(view(row))
            row.state = "deleting"
            return view(row)

    async def financial_inventory_ready(self, work):
        if work.closed_at is None:
            raise ValueError("Original closure time required")
        try:
            async with self.transaction() as session:
                # Registry/identity/lifecycle authority precedes owned(), whose
                # claim renewal can otherwise autoflush a Root write first.
                await session.execute(
                    text("SELECT public.account_require_financial_inventory(:s,:at)"),
                    {"s": work.subject, "at": work.closed_at},
                )
                await self.owned(session, work)
            return True
        except DBAPIError as exc:
            if getattr(exc.orig, "sqlstate", None) == "42501":
                return False
            raise

    async def prime_financial_inventory(self, work, tenant, owner, *, limit=100):
        commands = {
            "billing": text(
                "SELECT public.account_prime_billing_financial_sources(:s,:at,:t,:limit)"
            ),
            "payment": text(
                "SELECT public.payment_prime_financial_sources(:s,:at,:t,:limit)"
            ),
            "hypermesh": text(
                "SELECT public.hypermesh_prime_financial_sources(:s,:at,:t,:limit)"
            ),
        }
        if owner not in commands or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Bounded native inventory owner required")
        if work.closed_at is None:
            raise ValueError("Original closure time required")
        values = {"s": work.subject, "at": work.closed_at, "t": tenant, "limit": limit}
        async with self.transaction(tenant) as session:
            await session.execute(
                text("SELECT public.account_lock_financial_inventory(:s,:at,:t)"),
                values,
            )
            await self.owned(session, work)
            result = await session.scalar(commands[owner], values)
            if (
                not isinstance(result, dict)
                or set(result) != {"complete", "processed", "remaining"}
                or type(result["complete"]) is not bool
                or type(result["processed"]) is not int
                or type(result["remaining"]) is not int
                or not 0 <= result["processed"] <= limit
                or result["remaining"] < 0
                or result["complete"] != (result["remaining"] == 0)
            ):
                raise ValueError("Native inventory receipt unavailable")
            return result

    async def finish_source_free(self, work):
        """All current owners prove zero in the same native completion transaction."""
        if work.closed_at is None:
            raise ValueError("Original financial cleanup scope required")
        values = {"s": work.subject, "at": work.closed_at}
        async with self.transaction() as session:
            await session.execute(
                text("SELECT public.account_lock_financial_inventory(:s,:at,NULL)"), values
            )
            row = await self.owned(session, work)
            # Flush renewal before native completion clears the claim. An ORM
            # commit must not restore its pre-completion claim_until snapshot.
            await session.flush()
            receipt = await session.scalar(
                text("SELECT public.account_finish_source_free_closure(:s,:at,:epoch)"),
                {**values, "epoch": row.financial_epoch},
            )
            await session.refresh(row)
            if (not isinstance(receipt, dict) or set(receipt) != {"complete", "epoch", "remaining"}
                    or type(receipt["complete"]) is not bool
                    or type(receipt["epoch"]) is not int or receipt["epoch"] != row.financial_epoch
                    or type(receipt["remaining"]) is not int or receipt["remaining"] < 0
                    or receipt["complete"] != (receipt["remaining"] == 0)):
                raise ValueError("Native financial completion proof unavailable")
            return copy.deepcopy(receipt)

    async def erase_payer_risk(self, work, *, limit=100):
        """Fresh native risk-owner scan, never a whole-financial completion proof."""
        if work.closed_at is None or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Bounded original financial cleanup scope required")
        values = {"s": work.subject, "at": work.closed_at, "limit": limit}
        async with self.transaction() as session:
            await session.execute(
                text("SELECT public.account_lock_financial_inventory(:s,:at,NULL)"), values
            )
            row = await self.owned(session, work)
            if (row.state not in {"deleting", "deleted"}
                    or row.effects.get("personal_owners_erased") is not True):
                raise ValueError("Complete personal owner erasure required")
            receipt = await session.scalar(
                text("SELECT public.payment_erase_expired_payer_risk(:s,:at,:limit)"), values
            )
            if (not isinstance(receipt, dict)
                    or set(receipt) != {"complete", "processed", "remaining", "next_due_at"}
                    or type(receipt["complete"]) is not bool
                    or type(receipt["processed"]) is not int or receipt["processed"] not in {0, 1}
                    or type(receipt["remaining"]) is not int or receipt["remaining"] not in {0, 1}
                    or receipt["complete"] != (receipt["remaining"] == 0)
                    or (receipt["next_due_at"] is not None and not isinstance(receipt["next_due_at"], str))):
                raise ValueError("Native payer risk receipt unavailable")
            # The source DELETE advances the native epoch. Never cache a zero
            # across later evidence, and never overwrite native effects changes.
            await session.refresh(row, attribute_names=["effects", "financial_epoch"])
            progress = copy.deepcopy(row.effects.get("financial_gc", {}))
            progress["payer_risk"] = {
                "epoch": row.financial_epoch,
                "remaining": receipt["remaining"],
                "next_due_at": receipt["next_due_at"],
            }
            row.effects = {**row.effects, "financial_gc": progress}
            return copy.deepcopy(receipt)

    async def erase_host_associations(self, work, tenant, *, limit=100):
        return await self._erase_personal_associations(work, tenant, limit=limit, stage="host_associations")

    async def erase_company_creators(self, work, tenant, *, limit=100):
        return await self._erase_personal_associations(work, tenant, limit=limit, stage="company_creators")

    async def erase_payment_access(self, work, tenant, *, limit=100):
        return await self._erase_personal_associations(work, tenant, limit=limit, stage="payment_access")

    async def erase_device_reviewers(self, work, tenant, *, limit=100):
        return await self._erase_personal_associations(work, tenant, limit=limit, stage="device_reviewers")

    async def erase_runtime_credentials(self, work, tenant, *, limit=100):
        return await self._erase_personal_associations(work, tenant, limit=limit, stage="runtime_credentials")

    async def _erase_personal_associations(self, work, tenant, *, limit, stage):
        if work.closed_at is None or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Bounded original personal cleanup scope required")
        commands = {
            "host_associations": ("SELECT public.hypermesh_erase_personal_host_associations(:s,:at,:t,:limit)", 2 * limit + 1),
            "company_creators": ("SELECT public.account_erase_personal_company_creators(:s,:at,:t,:limit)", 2 * limit),
            "payment_access": ("SELECT public.payment_erase_personal_access(:s,:at,:t,:limit)", 2 * limit),
            "device_reviewers": ("SELECT public.hypermesh_erase_personal_device_reviewers(:s,:at,:t,:limit)", limit),
            "runtime_credentials": ("SELECT public.hypermesh_erase_personal_runtime(:s,:at,:t,:limit)", 3 * limit),
        }
        command, maximum = commands[stage]
        values = {"s": work.subject, "at": work.closed_at, "t": tenant, "limit": limit}
        async with self.transaction(tenant) as session:
            await session.execute(
                text("SELECT public.account_lock_financial_inventory(:s,:at,:t)"),
                values,
            )
            await session.execute(
                text("SELECT public.account_require_personal_erasure(:s,:t)"), values
            )
            row = await self.owned(session, work)
            if tenant is None:
                target = row
            else:
                target = await session.get(
                    AccountLifecycleScope,
                    (tenant, work.subject),
                    with_for_update=True,
                    populate_existing=True,
                )
                if target is None:
                    raise ValueError("Original personal cleanup scope required")
            effects = copy.deepcopy(target.effects)
            name, progress_name = stage + "_erasure", stage + "_progress"
            if name in effects:
                receipt = effects[name]
                if (
                    not isinstance(receipt, dict)
                    or set(receipt) != {"complete", "processed", "remaining"}
                    or receipt["complete"] is not True
                    or type(receipt["processed"]) is not int
                    or receipt["processed"] < 0
                    or type(receipt["remaining"]) is not int
                    or receipt["remaining"] != 0
                ):
                    raise ValueError("Native host cleanup receipt unavailable")
                return copy.deepcopy(receipt)
            progress = effects.get(progress_name, {"processed": 0})
            if (
                not isinstance(progress, dict)
                or set(progress) != {"processed"}
                or type(progress["processed"]) is not int
                or progress["processed"] < 0
            ):
                raise ValueError("Native host cleanup progress unavailable")
            receipt = await session.scalar(
                text(command),
                values,
            )
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"complete", "processed", "remaining"}
                or type(receipt["complete"]) is not bool
                or type(receipt["processed"]) is not int
                or not 0 <= receipt["processed"] <= maximum
                or type(receipt["remaining"]) is not int
                or receipt["remaining"] < 0
                or receipt["complete"] != (receipt["remaining"] == 0)
                or (stage in {"host_associations", "device_reviewers", "payment_access", "company_creators"} and not receipt["complete"] and receipt["processed"] == 0)
            ):
                raise ValueError("Native host cleanup receipt unavailable")
            # Native cleanup also records a durable recapture fence. Reload
            # before merging our receipt so an ORM snapshot cannot overwrite it.
            await session.refresh(target, attribute_names=["effects"])
            effects = copy.deepcopy(target.effects)
            receipt = {
                **receipt,
                "processed": progress["processed"] + receipt["processed"],
            }
            if receipt["complete"]:
                effects[name] = receipt
                effects.pop(progress_name, None)
            else:
                effects[progress_name] = {"processed": receipt["processed"]}
            # Native source changes and their cumulative receipt commit together.
            target.effects = effects
            return copy.deepcopy(receipt)

    async def purge_profile(self, work, tenant=None):
        from controlplane_tenancy.account_profile import purge_retired_profile

        async with self.transaction(tenant) as session:
            await session.execute(
                text("SELECT public.account_require_financial_inventory(:s,:at)"),
                {"s": work.subject, "at": work.closed_at},
            )
            await lock_identity(session, work.subject)
            row = await self.owned(session, work)
            if (
                row.state != "deleting"
                or row.closed_at is None
                or await self._database_now(session)
                < row.closed_at + _closure_retention()
                or row.effects.get("scope_discovery") is not True
            ):
                raise ValueError("Verified personal erasure must be started first")
            if tenant is None:
                owner = row.effects.get("platform_profile")
                if not isinstance(owner, dict) or not isinstance(
                    owner.get("user_ids"), list
                ):
                    raise ValueError(
                        "Complete original platform profile inventory required"
                    )
                effects = row.effects
            else:
                scope = await session.get(
                    AccountLifecycleScope,
                    (tenant, work.subject),
                    with_for_update=True,
                    populate_existing=True,
                )
                if (
                    scope is None
                    or scope.effects.get("profile_inventory_complete") is not True
                ):
                    raise ValueError("Complete original profile inventory required")
                owner, effects = {"user_ids": scope.user_ids}, scope.effects
            if "profile_erasure" in effects:
                return copy.deepcopy(effects["profile_erasure"])
            counts = await purge_retired_profile(
                session,
                tenant,
                work.subject,
                tuple(uuid.UUID(value) for value in owner["user_ids"]),
                verified_closed_at=row.closed_at,
                now=await self._database_now(session),
            )
            receipt = {
                "complete": True,
                "counts": counts,
                "at": (await self._database_now(session)).isoformat(),
            }
            if tenant is None:
                row.effects = {**row.effects, "profile_erasure": receipt}
            else:
                scope.effects = {**scope.effects, "profile_erasure": receipt}
            return copy.deepcopy(receipt)

    async def profiles_erased(self, work):
        tenants = self.completed_tenants(work)
        for tenant in tenants:
            scope = await self.scope_view(work, tenant)
            if (
                scope is None
                or scope["effects"].get("profile_erasure", {}).get("complete")
                is not True
            ):
                raise ValueError("Complete native profile erasure receipts required")
        async with self.transaction() as session:
            row = await self.owned(session, work)
            if (
                row.state != "deleting"
                or row.effects.get("profile_erasure", {}).get("complete") is not True
            ):
                raise ValueError("Complete platform profile erasure receipt required")
            row.profile_deleted_at = row.profile_deleted_at or await self._database_now(
                session
            )
            return view(row)

    @staticmethod
    def completed_tenants(work):
        identifiers = work.effects.get("scope_tenants")
        if work.effects.get("scope_discovery") is not True or not isinstance(
            identifiers, list
        ):
            raise ValueError("Original completed tenant inventory required")
        result = [uuid.UUID(value) for value in identifiers]
        if len(result) != len(set(result)) or len(result) > 100_000:
            raise ValueError("Complete distinct tenant inventory required")
        return result

    async def heartbeat(self, work):
        """Renew/check the claim between owner attempts, including failed ones."""
        async with self.transaction() as session:
            return view(await self.owned(session, work))
