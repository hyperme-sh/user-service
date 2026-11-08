"""Readiness refuses migrator credentials or an unbound TEST generation."""

import hashlib
from importlib.resources import files
import os
import re
from sqlalchemy import text

IMMUTABLE = (
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
                        """SELECT rolname,(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) privileged
            FROM pg_roles WHERE pg_has_role(session_user,oid,'SET') OR rolname=current_user"""
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
                        """SELECT c.relrowsecurity,c.relforcerowsecurity FROM pg_class c
                JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname=:table"""
                    ),
                    {"table": table},
                )
            ).one_or_none()
            if flags != (True, True):
                raise RuntimeError("Authority row security is missing")
        generation = os.environ.get("USER_TEST_FIXTURE_GENERATION")
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
