"""Fail closed before public closure enforcement uses a privileged database role."""

from __future__ import annotations

from controlplane_identity.account_lifecycle import enforcement_enabled, service_url
from sqlalchemy import text

# The public service may read exact retirement markers for membership admission;
# durable closure state and retirement writes belong to the private authority.
_PRIVATE_TABLES = (
    "public.account_lifecycles",
    "public.account_lifecycle_scopes",
    "public.identity_retirements",
    "public.account_financial_source_bindings",
    "public.account_financial_fence_versions",
    "public.account_financial_transitions",
    "public.financial_accounting_totals",
)
_PRIVATE_FUNCTIONS = (
    "public.account_check_closure_worker_installation()",
    "public.account_merge_anonymous_total(text,text,text,numeric)",
    "public.account_issue_financial_transition(text,timestamp with time zone,uuid,text[],text,text,text,jsonb,jsonb,bigint)",
    "public.hypermesh_erase_personal_host_associations(text,timestamp with time zone,uuid,integer)",
    "public.hypermesh_erase_personal_runtime(text,timestamp with time zone,uuid,integer)",
    "public.hypermesh_erase_personal_device_reviewers(text,timestamp with time zone,uuid,integer)",
    "public.payment_erase_personal_access(text,timestamp with time zone,uuid,integer)",
    "public.account_finish_source_free_closure(text,timestamp with time zone,bigint)",
    "public.payment_erase_expired_payer_risk(text,timestamp with time zone,integer)",
    "public.account_erase_personal_company_creators(text,timestamp with time zone,uuid,integer)",
)


async def check_public_database(engine):
    if not enforcement_enabled():
        return
    service_url("ACCOUNT_CLOSURE_AUTHORITY_URL")
    async with engine.begin() as connection:
        await connection.execute(text("SET LOCAL statement_timeout='5000ms'"))
        roles = (await connection.execute(text(
            "SELECT rolname,(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) FROM pg_catalog.pg_roles "
            "WHERE pg_has_role(session_user,oid,'SET') OR rolname=current_user LIMIT 1001"
        ))).all()
        if not roles or len(roles) > 1000:
            raise RuntimeError("Public closure database role inventory unavailable")
        for name, privileged in roles:
            if privileged:
                raise RuntimeError("Public closure database role is privileged")
            for table in _PRIVATE_TABLES:
                # Missing tables fail closed. Check column grants too: a grant
                # on financial_hold alone is enough to bypass a preservation hold.
                privileges = "INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER"
                columns = "INSERT,UPDATE,REFERENCES"
                if table not in {"public.identity_retirements", "public.financial_accounting_totals"}:
                    # Raw global lifecycle/source inventories also stay private.
                    # Retirement admission and anonymous accounting reads contain
                    # none of those resource or financial-source inventories.
                    privileges += ",SELECT"
                    columns += ",SELECT"
                if await connection.scalar(text(
                    "SELECT has_table_privilege(:role,:table,:privileges) "
                    "OR has_any_column_privilege(:role,:table,:columns)"
                ), {"role": name, "table": table, "privileges": privileges, "columns": columns}) is not False:
                    raise RuntimeError("Public closure database role can access private state")
            for signature in _PRIVATE_FUNCTIONS:
                if await connection.scalar(text(
                    "SELECT has_function_privilege(:role,CAST(:signature AS regprocedure),'EXECUTE')"
                ), {"role": name, "signature": signature}) is not False:
                    raise RuntimeError("Public closure database role can execute private work")
            # Inspect installed native definer functions too; a selective grant
            # or a future owner entrypoint must not bypass a fixed name list.
            if await connection.scalar(text(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='public' AND p.prosecdef "
                "AND p.proname ~ '^(account_|payment_|hypermesh_|platform_)' "
                "AND has_function_privilege(:role,p.oid,'EXECUTE'))"
            ), {"role": name}) is not False:
                raise RuntimeError("Public closure database role can execute native definer work")
        if await connection.scalar(text(
            "SELECT has_table_privilege(current_user,'public.identity_retirements','SELECT')"
        )) is not True:
            raise RuntimeError("Public closure database role cannot read retirement markers")
