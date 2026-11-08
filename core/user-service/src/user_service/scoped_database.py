"""Readiness refuses migrator credentials or an unbound TEST generation."""

import hashlib
from importlib.resources import files
import os
import re
from sqlalchemy import text

IMMUTABLE = (
    "owner_schema_version",
    "owner_authority_version",
    "authority_host_owners",
    "authority_networks",
    "authority_network_admins",
    "authority_tenants",
    "authority_fixture_accounts",
    "authority_fixture_generation",
)
RLS = (
    "authority_host_owners",
    "users",
    "roles",
    "organizations",
    "authority_networks",
    "authority_network_admins",
    "authority_tenants",
    "organization_memberships",
    "authority_fixture_accounts",
)


async def check(engine):
    if os.environ.get("USER_SCOPED_AUTHORITY_REQUIRED") != "1":
        if os.environ.get("USER_TEST_FIXTURE_GENERATION"):
            raise RuntimeError("Canonical TEST generation requires scoped authority")
        # A sealed canonical database must never silently select legacy guards,
        # even when every generation environment binding was omitted.
        async with engine.begin() as db:
            relation = await db.scalar(
                text("SELECT to_regclass('authority_fixture_generation')")
            )
            if relation is not None and await db.scalar(
                text("SELECT count(*) FROM authority_fixture_generation")
            ):
                raise RuntimeError("Seeded TEST generation requires scoped authority")
        return
    expected = hashlib.sha256(
        files("user_service").joinpath("authority_schema.sql").read_bytes()
    ).hexdigest()
    async with engine.begin() as db:
        schema = await db.scalar(text("SELECT current_schema()"))
        if not schema or schema == "public":
            raise RuntimeError("Scoped User runtime requires its own schema")
        versions = (
            await db.execute(
                text("SELECT revision,sha256 FROM owner_authority_version")
            )
        ).all()
        if versions != [("0002_authority", expected)]:
            raise RuntimeError("Authority schema identity differs")
        roles = (
            (
                await db.execute(
                    text(
                        """WITH RECURSIVE reachable(oid) AS (
                SELECT oid FROM pg_roles WHERE rolname IN (session_user,current_user)
                UNION SELECT m.roleid FROM pg_auth_members m JOIN reachable r ON m.member=r.oid
                WHERE m.inherit_option OR m.set_option
            ) SELECT rolname,(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) privileged
              FROM pg_roles WHERE oid IN (SELECT oid FROM reachable)"""
                    )
                )
            )
            .mappings()
            .all()
        )
        if not roles or len(roles) > 100:
            raise RuntimeError("Runtime role inventory unavailable")
        for role in roles:
            if role["privileged"] or await db.scalar(
                text("SELECT has_schema_privilege(:role,current_schema(),'CREATE')"),
                {"role": role["rolname"]},
            ):
                raise RuntimeError(
                    "Bootstrap/migrator authority cannot be a runtime credential"
                )
            if await db.scalar(
                text(
                    """SELECT EXISTS(SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
                WHERE n.nspname=current_schema() AND r.rolname=:role
                  AND c.relkind IN ('r','p','v','m','f','S'))"""
                ),
                {"role": role["rolname"]},
            ):
                raise RuntimeError(
                    "Runtime owns an authority RLS table or other owner relation"
                )
            for table in IMMUTABLE:
                if await db.scalar(
                    text(
                        "SELECT has_table_privilege(:role,:table,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') OR has_any_column_privilege(:role,:table,'INSERT,UPDATE,REFERENCES')"
                    ),
                    {"role": role["rolname"], "table": table},
                ):
                    raise RuntimeError("Runtime can modify configured authority")
        for table in RLS:
            flags = (
                await db.execute(
                    text(
                        """SELECT c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner) FROM pg_class c
                JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname=:table"""
                    ),
                    {"table": table},
                )
            ).one_or_none()
            if flags is None or tuple(flags[:2]) != (True, True):
                raise RuntimeError("Authority row security is missing")
            if flags[2] in {role["rolname"] for role in roles}:
                raise RuntimeError("Runtime owns an authority RLS table")
        generation = os.environ.get("USER_TEST_FIXTURE_GENERATION")
        if not generation and await db.scalar(
            text("SELECT count(*) FROM authority_fixture_generation")
        ):
            raise RuntimeError(
                "Seeded TEST generation requires explicit readiness bindings"
            )
        if generation:
            manifest = os.environ.get("USER_TEST_FIXTURE_SHA256", "")
            source = os.environ.get("GIT_SHA", "")
            if (
                re.fullmatch("[a-f0-9]{64}", manifest) is None
                or re.fullmatch("[a-f0-9]{40}", source) is None
            ):
                raise RuntimeError("Exact TEST manifest and source bindings required")
            row = (
                await db.execute(
                    text(
                        "SELECT generation,manifest_sha256,source_sha FROM authority_fixture_generation"
                    )
                )
            ).one_or_none()
            if row != (generation, manifest, source):
                raise RuntimeError(
                    "Configured fixture generation is not seeded for this runtime"
                )
