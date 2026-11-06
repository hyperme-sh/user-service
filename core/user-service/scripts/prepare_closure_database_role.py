"""Print a DBA-reviewed private role plan; never connect or apply it."""

from __future__ import annotations

import argparse
import re

_FUNCTIONS = (
    "account_check_closure_worker_installation()",
    "account_test_data_enabled()",
    "account_require_financial_inventory(text,timestamptz)",
    "account_lock_financial_inventory(text,timestamptz,uuid)",
    "account_prime_billing_financial_sources(text,timestamptz,uuid,integer)",
    "payment_prime_financial_sources(text,timestamptz,uuid,integer)",
    "hypermesh_prime_financial_sources(text,timestamptz,uuid,integer)",
    "account_finish_source_free_closure(text,timestamptz,bigint)",
    "payment_erase_expired_payer_risk(text,timestamptz,integer)",
    "account_require_personal_erasure(text,uuid)",
    "account_erase_personal_company_creators(text,timestamptz,uuid,integer)",
    "payment_erase_personal_access(text,timestamptz,uuid,integer)",
    "hypermesh_erase_personal_host_associations(text,timestamptz,uuid,integer)",
    "hypermesh_erase_personal_runtime(text,timestamptz,uuid,integer)",
    "hypermesh_erase_personal_device_reviewers(text,timestamptz,uuid,integer)",
)


def render_sql(role, database, *, test_retention=False):
    if type(test_retention) is not bool:
        raise ValueError("Explicit boolean TEST retention selection required")
    if not isinstance(role, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", role):
        raise ValueError("A new lowercase PostgreSQL role name is required")
    if not isinstance(database, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{0,62}", database
    ):
        raise ValueError("An exact lowercase PostgreSQL database name is required")
    target = f'"{role}"'
    statements = [
        "BEGIN;",
        # CREATE fails if the role already exists: never reuse unknown grants.
        f"CREATE ROLE {target} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;",
        f'GRANT CONNECT ON DATABASE "{database}" TO {target};',
        f"GRANT USAGE ON SCHEMA public TO {target};",
        f"GRANT SELECT ON public.tenants TO {target};",
        f"GRANT SELECT, UPDATE ON public.users TO {target};",
        f"GRANT SELECT, INSERT ON public.identity_retirements TO {target};",
        f"GRANT SELECT, INSERT, UPDATE ON public.account_lifecycles, public.account_lifecycle_scopes TO {target};",
        (
            f"GRANT SELECT, DELETE ON public.user_preferences, public.user_password_resets, public.user_magic_links, "
            f"public.user_group_memberships, public.user_passkeys, public.user_passkey_challenges, "
            f"public.user_wallet_bindings, public.chat_sessions_ai, public.chat_histories_ai TO {target};"
        ),
        f"GRANT UPDATE(id) ON public.chat_sessions_ai, public.chat_histories_ai TO {target};",
        *(
            f"GRANT EXECUTE ON FUNCTION public.{signature} TO {target};"
            for signature in _FUNCTIONS
        ),
        "COMMIT;",
    ]
    if test_retention:
        # This mode is administrative, private and unavailable on a production
        # database. The role cannot change or read the protected policy marker.
        from controlplane_db.test_retention import financial_tables

        names = financial_tables()
        if any(not re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in names):
            raise ValueError("Invalid native financial table inventory")
        tables = ", ".join("'" + name + "'" for name in sorted(names))
        statements[-1:-1] = [
            "DO $$ BEGIN IF NOT public.account_test_data_enabled() THEN RAISE EXCEPTION 'A database-bound TEST policy is required'; END IF; END $$;",
            f"GRANT EXECUTE ON FUNCTION public.account_lock_test_data_policy(), public.hypermesh_financial_parties(text,jsonb), public.account_lock_test_financial_sources(text,timestamptz), public.account_stage_test_delete(text,timestamptz,oid,text,oid,text), public.account_delete_test_financial_row(text,timestamptz,oid,text), public.account_clear_test_delete_capabilities(), public.account_reconcile_test_financial_bindings(text,timestamptz) TO {target};",
            f"GRANT SELECT ON public.account_financial_source_bindings TO {target};",
            f"DO $$ DECLARE name text; BEGIN FOREACH name IN ARRAY ARRAY[{tables}] LOOP IF to_regclass('public.'||quote_ident(name)) IS NOT NULL THEN EXECUTE format('GRANT SELECT ON public.%I TO %I',name,'{role}'); END IF; END LOOP; END $$;",
        ]
    return "\n".join(statements) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument(
        "--test-retention",
        action="store_true",
        help="Private TEST financial erasure grants; requires an already configured TEST database",
    )
    args = parser.parse_args()
    try:
        plan = render_sql(args.role, args.database, test_retention=args.test_retention)
    except ValueError as error:
        parser.error(str(error))
    print(plan, end="")


if __name__ == "__main__":
    main()
