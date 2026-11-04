"""Print a DBA-reviewed private role plan; never connect or apply it."""

from __future__ import annotations

import argparse
import re

_FUNCTIONS = (
    "account_check_closure_worker_installation()",
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


def render_sql(role, database):
    if not isinstance(role, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", role):
        raise ValueError("A new lowercase PostgreSQL role name is required")
    if not isinstance(database, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", database):
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
        (f"GRANT SELECT, DELETE ON public.user_preferences, public.user_password_resets, public.user_magic_links, "
        f"public.user_group_memberships, public.user_passkeys, public.user_passkey_challenges, "
        f"public.user_wallet_bindings, public.chat_sessions_ai, public.chat_histories_ai TO {target};"),
        f"GRANT UPDATE(id) ON public.chat_sessions_ai, public.chat_histories_ai TO {target};",
        *(f"GRANT EXECUTE ON FUNCTION public.{signature} TO {target};" for signature in _FUNCTIONS),
        "COMMIT;",
    ]
    return "\n".join(statements) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True)
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    try:
        plan = render_sql(args.role, args.database)
    except ValueError as error:
        parser.error(str(error))
    print(plan, end="")


if __name__ == "__main__":
    main()
