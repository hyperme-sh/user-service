"""The proposed DBA plan runs actual closure without financial source DML."""

import importlib.util
import hashlib
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from controlplane_db.models import User
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_jobs import ClosureJobs
from user_service.closure_worker import ClosureWorker, WorkerUnavailable, check_database
from user_service.models import AccountLifecycle

spec = importlib.util.spec_from_file_location(
    "closure_role_plan",
    Path(__file__).parents[1] / "scripts/prepare_closure_database_role.py",
)
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


@pytest.mark.parametrize("role", ["", "PUBLIC", "x;drop role y", 'x"', "x" * 64, None])
def test_invalid_role_names_cannot_change_the_plan(role):
    with pytest.raises(ValueError):
        plan.render_sql(role, "test")


@pytest.mark.parametrize("test_retention", [False, True])
async def test_private_role_plan_closes_real_profile_without_source_dml(
    jobs, jobs_url, monkeypatch, test_retention
):
    store, _ = jobs
    role, password = "closure_worker_" + uuid.uuid4().hex, uuid.uuid4().hex
    # Apply the reviewed plan only inside this owned, disposable database.
    monkeypatch.setenv("FASTAPI_ENV", "test" if test_retention else "production")
    monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
    if test_retention:
        async with store.transaction() as session:
            await session.execute(
                text(
                    "INSERT INTO account_test_data_policy(singleton,database_oid,database_name,enabled) VALUES(true,(SELECT oid FROM pg_database WHERE datname=current_database()),current_database(),true)"
                )
            )
    statements = plan.render_sql(
        role, "test", test_retention=test_retention
    ).splitlines()
    async with store.transaction() as session:
        for statement in statements[1:-1]:
            await session.execute(text(statement))
        await session.execute(text(f"ALTER ROLE {role} LOGIN PASSWORD '{password}'"))
        identifier, subject = uuid.uuid4(), str(uuid.uuid4())
        session.add(
            User(
                id=identifier,
                tenant_id=None,
                keycloak_sub=subject,
                email=f"{subject}@example.invalid",
                first_name="Person",
                last_name="Closing",
                gender="unspecified",
                is_active=True,
            )
        )
        if test_retention:
            await session.execute(
                text(
                    "INSERT INTO payer_mismatch_accounts(account_key,day) VALUES(:key,CURRENT_DATE)"
                ),
                {"key": hashlib.sha256(subject.encode()).hexdigest()},
            )
    engine = create_async_engine(
        make_url(jobs_url).set(
            drivername="postgresql+asyncpg", username=role, password=password
        )
    )
    try:
        await check_database(engine)
        native = ClosureJobs(
            async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        )
        await native.request(subject, subject, "self_service")
        if test_retention:
            async with store.transaction() as session:
                await session.execute(
                    text(
                        "UPDATE account_lifecycles SET financial_hold=true,hold_reference='native-test-hold' WHERE subject=:s"
                    ),
                    {"s": subject},
                )
        monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", "none")
        identity, owners = AsyncMock(), AsyncMock()
        owners.key_tenants.return_value = []
        worker = ClosureWorker(native, identity, owners)
        failures = []
        dispatch = worker._dispatch

        async def observed(work):
            try:
                await dispatch(work)
            except Exception as error:
                failures.append(error)
                raise

        worker._dispatch = observed
        purge = native.purge_profile

        async def observed_purge(*args):
            try:
                return await purge(*args)
            except Exception as error:
                failures.append(error)
                raise

        native.purge_profile = observed_purge
        claim = native.claim
        native.claim = lambda: claim(subject)
        for _ in range(3):
            assert await worker.run_one()
            async with native.transaction() as session:
                await session.execute(
                    text(
                        "UPDATE account_lifecycles SET retry_at=transaction_timestamp() WHERE subject=:s"
                    ),
                    {"s": subject},
                )
        async with native.transaction() as session:
            row = await session.get(AccountLifecycle, subject)
            user = await session.get(User, identifier)
            assert not failures, failures
            assert row.state == "deleted" and row.financial_deleted_at is not None, (
                row.last_error,
                row.effects,
            )
            assert user.keycloak_sub is None and user.deleted_at is not None
            assert user.email != f"{subject}@example.invalid"
            if test_retention:
                assert row.effects["test_financial_erasure"] == {
                    "complete": True,
                    "roots_complete": True,
                    "remaining": 0,
                    "deleted": 1,
                    "tables": {"payer_mismatch_accounts": 1},
                }
        if test_retention:
            async with native.transaction() as session:
                assert (
                    await session.scalar(
                        text(
                            "SELECT count(*) FROM payer_mismatch_accounts WHERE account_key=:key"
                        ),
                        {"key": hashlib.sha256(subject.encode()).hexdigest()},
                    )
                    == 0
                )
        forbidden = ["DELETE FROM billing_records WHERE false"] + (
            [
                "SELECT * FROM account_test_data_policy",
                "UPDATE account_test_data_policy SET enabled=false",
                "DELETE FROM account_test_delete_capabilities WHERE false",
                "DELETE FROM account_financial_source_bindings WHERE false",
            ]
            if test_retention
            else []
        )
        for command in (
            *forbidden,
            "DELETE FROM account_lifecycles WHERE false",
            "DELETE FROM identity_retirements WHERE false",
            "CREATE TABLE public.closure_unwanted(id integer)",
        ):
            async with native.transaction() as session:
                with pytest.raises(DBAPIError, match="permission denied"):
                    await session.execute(text(command))
        if test_retention:
            for privilege, table in (
                ("SELECT", "account_test_delete_capabilities"),
                ("DELETE", "billing_records"),
                ("DELETE", "account_financial_source_bindings"),
                ("SELECT(row_digest)", "account_test_delete_capabilities"),
                ("INSERT(row_digest)", "account_test_delete_capabilities"),
                ("UPDATE(row_digest)", "account_test_delete_capabilities"),
                ("UPDATE(livemode)", "connect_recipient_accounts"),
                ("INSERT(amount)", "billing_records"),
                ("UPDATE(resource)", "account_financial_source_bindings"),
            ):
                async with store.transaction() as session:
                    await session.execute(text(f"GRANT {privilege} ON public.{table} TO {role}"))
                try:
                    with pytest.raises(WorkerUnavailable):
                        await check_database(engine)
                finally:
                    async with store.transaction() as session:
                        await session.execute(text(f"REVOKE {privilege} ON public.{table} FROM {role}"))
                await check_database(engine)
    finally:
        await engine.dispose()
        async with store.transaction() as session:
            await session.execute(text(f"DROP OWNED BY {role}"))
            await session.execute(text(f"DROP ROLE {role}"))
            if test_retention:
                await session.execute(text("DELETE FROM account_test_data_policy"))
