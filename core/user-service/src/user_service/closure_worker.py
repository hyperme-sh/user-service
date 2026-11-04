"""Private bounded closure worker; whole financial completion remains gated."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import signal
import sys

import httpx
from controlplane_identity.account_lifecycle import (
    enforcement_enabled,
    service_secret,
    service_url,
)
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from user_service.closure_clients import ClosureOwners
from user_service.closure_erasure import PersonalErasure
from user_service.closure_idp import KeycloakClosureClient
from user_service.closure_jobs import ClosureClaimLost, ClosureJobs
from user_service.closure_processor import ClosureProcessor

HEARTBEAT_SECONDS = 15


class WorkerUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("Account closure worker unavailable")


async def check_database(engine):
    """A tenant reader must never interpret RLS-hidden lifecycle rows as empty."""
    async with engine.begin() as connection:
        await connection.execute(text("SET LOCAL lock_timeout='2000ms'"))
        await connection.execute(text("SET LOCAL statement_timeout='10000ms'"))
        privileged = await connection.scalar(
            text(
                "SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user"
            )
        )
        if privileged is not True:
            raise WorkerUnavailable()
        await connection.execute(text("SET LOCAL row_security=off"))
        # Resolve and check the private entrypoints before claiming any work.
        for signature in (
            "public.account_require_financial_inventory(text,timestamp with time zone)",
            "public.account_finish_source_free_closure(text,timestamp with time zone,bigint)",
            "public.payment_erase_expired_payer_risk(text,timestamp with time zone,integer)",
            "public.account_erase_personal_company_creators(text,timestamp with time zone,uuid,integer)",
        ):
            if (
                await connection.scalar(
                    text(
                        "SELECT has_function_privilege(current_user,CAST(:signature AS regprocedure),'EXECUTE')"
                    ),
                    {"signature": signature},
                )
                is not True
            ):
                raise WorkerUnavailable()
        # Installed producer coverage is mandatory even when there are no roots.
        await connection.execute(
            text("SELECT public.account_check_closure_worker_installation()")
        )
        await connection.execute(
            text("SELECT subject FROM public.account_lifecycles LIMIT 1")
        )


class ClosureWorker:
    def __init__(self, jobs, identity, owners):
        self.jobs = jobs
        self.processor = ClosureProcessor(jobs, identity, owners)
        self.personal = PersonalErasure(jobs, identity, owners)

    async def _dispatch(self, work):
        if work.state == "closing":
            await self.processor.close(work)
        elif work.state in {"closed", "deleting"}:
            if work.effects.get("personal_owners_erased") is True:
                await self.jobs.erase_payer_risk(work)
                receipt = await self.jobs.finish_source_free(work)
                if not receipt["complete"]:
                    await self.jobs.release(work, error="deadline_pending")
            else:
                await self.personal.erase(work)
        else:
            # Financial expiry needs its own owner implementation and proofs.
            # Neither an absent producer nor a completed personal stage is zero.
            await self.jobs.release(work, error="deadline_pending")

    async def _renew(self, work):
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            await self.jobs.heartbeat(work)

    async def run_one(self):
        work = await self.jobs.claim()
        if work is None:
            return False
        operation = asyncio.create_task(self._dispatch(work))
        renewal = asyncio.create_task(self._renew(work))
        try:
            done, _ = await asyncio.wait(
                (operation, renewal), return_when=asyncio.FIRST_COMPLETED
            )
            if operation in done:
                await operation
            else:
                # Cancel in-flight HTTP work before retrying or relinquishing
                # authority. A replacement claimant owns all later receipts.
                await renewal
        except ClosureClaimLost:
            pass
        except asyncio.CancelledError:
            operation.cancel()
            await asyncio.gather(operation, return_exceptions=True)
            with contextlib.suppress(ClosureClaimLost, DBAPIError):
                await self.jobs.release(work, error="owner_unavailable")
            raise
        except Exception:  # noqa: BLE001 - sanitize private job failures without exposing payloads
            operation.cancel()
            await asyncio.gather(operation, return_exceptions=True)
            with contextlib.suppress(ClosureClaimLost):
                await self.jobs.release(work, error="owner_conflict")
        finally:
            operation.cancel()
            renewal.cancel()
            await asyncio.gather(operation, renewal, return_exceptions=True)
        return True

    async def run(self, *, max_jobs):
        if type(max_jobs) is not int or not 1 <= max_jobs <= 100:
            raise ValueError("Worker batch must contain 1 to 100 jobs")
        attempted = 0
        while attempted < max_jobs and await self.run_one():
            attempted += 1
        return attempted


def database_url():
    """Use a dedicated private DSN; never fall back to the public service DSN."""
    try:
        value = os.environ["ACCOUNT_CLOSURE_WORKER_DATABASE_URL"]
        parsed = make_url(value)
        if (
            parsed.drivername != "postgresql+asyncpg"
            or not parsed.host
            or not parsed.database
            or not parsed.username
            or not parsed.password
        ):
            raise ValueError
        return value
    except (KeyError, ValueError, ArgumentError):
        raise WorkerUnavailable() from None


async def execute(*, max_jobs):
    if (
        os.environ.get("ACCOUNT_CLOSURE_WORKER_ENABLED", "").lower() != "true"
        or not enforcement_enabled()
    ):
        raise WorkerUnavailable()
    # Validate fixed purpose credentials/destinations before acquiring a claim.
    service_secret("ACCOUNT_CLOSURE_GUARD_TOKEN")
    service_secret("ACCOUNT_CLOSURE_OPERATIONS_TOKEN")
    for name in ("ACCOUNT_CLOSURE_KEYS_URL", "ACCOUNT_CLOSURE_HYPERMESH_URL"):
        service_url(name)
    engine = create_async_engine(database_url(), pool_pre_ping=True, echo=False)
    try:
        await check_database(engine)
        async with httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=5
        ) as client:
            identity = KeycloakClosureClient(client)
            jobs = ClosureJobs(
                async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
            )
            return await ClosureWorker(jobs, identity, ClosureOwners(client)).run(
                max_jobs=max_jobs
            )
    finally:
        await engine.dispose()


async def run_command(*, max_jobs):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        return await execute(max_jobs=max_jobs)
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-jobs", type=int, choices=range(1, 101), default=1)
    args = parser.parse_args()
    try:
        asyncio.run(run_command(max_jobs=args.max_jobs))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except Exception:  # noqa: BLE001 - sanitize private job failures without exposing payloads
        # No DSNs, provider bodies, subjects or exception traces on stdout/stderr.
        print("Account closure worker unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
