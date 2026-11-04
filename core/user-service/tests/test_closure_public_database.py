"""Public startup rejects actual native grants, including columns and SET ROLE."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from user_service.closure_public_database import check_public_database


@pytest.fixture
async def public_role(jobs, jobs_url, monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_AUTHORITY_URL", "https://closure.internal")
    store, _ = jobs
    role, password = "closure_public_" + uuid.uuid4().hex, uuid.uuid4().hex
    async with store.transaction() as session:
        await session.execute(text(f"CREATE ROLE {role} LOGIN NOINHERIT PASSWORD '{password}'"))
        await session.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        await session.execute(text(f"GRANT SELECT ON public.identity_retirements TO {role}"))
    engine = create_async_engine(make_url(jobs_url).set(drivername="postgresql+asyncpg", username=role, password=password))
    try:
        yield store, role, engine
    finally:
        await engine.dispose()
        async with store.transaction() as session:
            await session.execute(text(f"DROP OWNED BY {role}"))
            await session.execute(text(f"DROP ROLE {role}"))


async def test_readonly_marker_role_passes_without_private_database_authority(public_role):
    _, _, engine = public_role
    await check_public_database(engine)


@pytest.mark.parametrize("grant", [
    "GRANT UPDATE ON public.account_lifecycles TO {role}",
    "GRANT SELECT(subject) ON public.account_lifecycles TO {role}",
    "GRANT SELECT ON public.account_lifecycle_scopes TO {role}",
    "GRANT SELECT(resource) ON public.account_financial_source_bindings TO {role}",
    "GRANT UPDATE(financial_hold) ON public.account_lifecycles TO {role}",
    "GRANT INSERT(subject) ON public.identity_retirements TO {role}",
    "GRANT UPDATE(effects) ON public.account_lifecycle_scopes TO {role}",
    "GRANT DELETE ON public.account_financial_source_bindings TO {role}",
    "GRANT UPDATE ON public.account_financial_fence_versions TO {role}",
    "GRANT UPDATE ON public.account_financial_transitions TO {role}",
    "GRANT INSERT ON public.financial_accounting_totals TO {role}",
    "GRANT EXECUTE ON FUNCTION public.account_merge_anonymous_total(text,text,text,numeric) TO {role}",
    "GRANT EXECUTE ON FUNCTION public.account_finish_source_free_closure(text,timestamptz,bigint) TO {role}",
])
async def test_private_table_column_and_function_grants_fail_startup(public_role, grant):
    store, role, engine = public_role
    async with store.transaction() as session:
        await session.execute(text(grant.format(role=role)))
    with pytest.raises(RuntimeError, match="can access private state|can execute private work"):
        await check_public_database(engine)


async def test_noinherit_membership_cannot_hide_a_settable_privileged_role(public_role):
    store, role, engine = public_role
    group = "closure_group_" + uuid.uuid4().hex
    async with store.transaction() as session:
        await session.execute(text(f"CREATE ROLE {group} BYPASSRLS"))
        await session.execute(text(f"GRANT {group} TO {role}"))
    try:
        with pytest.raises(RuntimeError, match="is privileged"):
            await check_public_database(engine)
    finally:
        async with store.transaction() as session:
            await session.execute(text(f"REVOKE {group} FROM {role}"))
            await session.execute(text(f"DROP ROLE {group}"))


async def test_public_role_must_read_retirement_markers(public_role):
    store, role, engine = public_role
    async with store.transaction() as session:
        await session.execute(text(f"REVOKE SELECT ON public.identity_retirements FROM {role}"))
    with pytest.raises(RuntimeError, match="cannot read retirement markers"):
        await check_public_database(engine)


async def test_default_off_does_not_connect_or_require_authority_url(monkeypatch):
    monkeypatch.delenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", raising=False)
    monkeypatch.delenv("ACCOUNT_CLOSURE_AUTHORITY_URL", raising=False)
    await check_public_database(None)


async def test_future_native_definer_grant_is_discovered_without_a_name_list(public_role):
    store, _, engine = public_role
    name = "account_review_probe_" + uuid.uuid4().hex
    async with store.transaction() as session:
        # Owned disposable database only. No application data is changed.
        await session.execute(text(f"CREATE FUNCTION public.{name}() RETURNS boolean "
                                   "LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT true'"))
    try:
        with pytest.raises(RuntimeError, match="can execute native definer work"):
            await check_public_database(engine)
    finally:
        async with store.transaction() as session:
            await session.execute(text(f"DROP FUNCTION public.{name}()"))


@pytest.mark.parametrize("attribute", ["CREATEROLE", "CREATEDB", "REPLICATION"])
async def test_public_role_cannot_keep_administrative_privileges(public_role, attribute):
    store, role, engine = public_role
    async with store.transaction() as session:
        await session.execute(text(f"ALTER ROLE {role} {attribute}"))
    with pytest.raises(RuntimeError, match="is privileged"):
        await check_public_database(engine)


async def test_limited_public_role_can_enroll_but_reads_native_retirement(public_role):
    from controlplane_tenancy.tenant_membership import create_tenant_membership_row
    from sqlalchemy.ext.asyncio import async_sessionmaker

    store, role, engine = public_role
    tenant, open_subject, retired_subject = uuid.uuid4(), str(uuid.uuid4()), str(uuid.uuid4())
    async with store.transaction() as session:
        await session.execute(text("INSERT INTO tenants(id,name,is_active) VALUES(:t,'public-role-test',true)"), {"t": tenant})
        await session.execute(text(f"GRANT SELECT, INSERT ON public.users TO {role}"))
    await store.request(retired_subject, retired_subject, "self_service")
    await check_public_database(engine)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    for subject in (open_subject, retired_subject):
        async with maker.begin() as session:
            await session.execute(text("SELECT set_config('app.current_tenant_id',:t,true)"), {"t": str(tenant)})
            async def enroll(subject=subject):
                return await create_tenant_membership_row(session, tenant, email=f"{subject}@example.invalid",
                    first_name="Public", last_name="Role", keycloak_sub=subject)
            if subject == retired_subject:
                with pytest.raises(ValueError, match="retired"):
                    await enroll()
            else:
                assert (await enroll()).keycloak_sub == open_subject


async def test_restricted_startup_role_cannot_hide_authenticated_superuser(public_role, jobs_url):
    _, role, _ = public_role
    engine = create_async_engine(make_url(jobs_url).set(drivername="postgresql+asyncpg"),
                                 connect_args={"server_settings": {"role": role}})
    try:
        async with engine.connect() as connection:
            assert await connection.scalar(text("SELECT current_user")) == role
            assert await connection.scalar(text("SELECT session_user")) != role
        with pytest.raises(RuntimeError, match="is privileged|can access private state"):
            await check_public_database(engine)
    finally:
        await engine.dispose()


async def test_restricted_startup_role_cannot_hide_session_user_private_grants(public_role, jobs_url):
    store, role, _ = public_role
    login, password = "closure_login_" + uuid.uuid4().hex, uuid.uuid4().hex
    async with store.transaction() as session:
        await session.execute(text(f"CREATE ROLE {login} LOGIN NOINHERIT PASSWORD '{password}'"))
        await session.execute(text(f"GRANT {role} TO {login}"))
        await session.execute(text(f"GRANT UPDATE ON public.account_lifecycles TO {login}"))
    engine = create_async_engine(make_url(jobs_url).set(drivername="postgresql+asyncpg", username=login, password=password),
                                 connect_args={"server_settings": {"role": role}})
    try:
        async with engine.connect() as connection:
            assert await connection.scalar(text("SELECT current_user")) == role
            assert await connection.scalar(text("SELECT session_user")) == login
        with pytest.raises(RuntimeError, match="can access private state"):
            await check_public_database(engine)
    finally:
        await engine.dispose()
        async with store.transaction() as session:
            await session.execute(text(f"DROP OWNED BY {login}"))
            await session.execute(text(f"DROP ROLE {login}"))
