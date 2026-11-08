"""Add explicit authority scopes without rewriting the owner baseline."""

import argparse
import hashlib
from importlib.resources import files
from pathlib import Path
from sqlalchemy import create_engine, text


def install(engine):
    ddl = files("user_service").joinpath("authority_schema.sql").read_text()
    digest = hashlib.sha256(ddl.encode()).hexdigest()
    with engine.begin() as db:
        row = (
            db.execute(
                text(
                    """SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication,n.nspowner=r.oid AS owns_schema,n.nspname
            FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema() WHERE r.rolname=current_user"""
                )
            )
            .mappings()
            .one()
        )
        if (
            any(
                row[key]
                for key in [
                    "rolsuper",
                    "rolbypassrls",
                    "rolcreaterole",
                    "rolcreatedb",
                    "rolreplication",
                ]
            )
            or not row["owns_schema"]
            or row["nspname"] == "public"
        ):
            raise ValueError(
                "Authority migration requires a nonprivileged owner schema"
            )
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))")
        )
        if (
            db.scalar(
                text("SELECT to_regclass(current_schema()||'.owner_schema_version')")
            )
            is None
        ):
            raise ValueError("Install the User owner baseline first")
        # Immutable baseline is shipped in the separate image-local owner bundle.
        baseline = "440fb48049959f5b3a8338ec0ba21e32b91e6ec23628e5bcc7191092b12b2e03"
        if db.execute(
            text("SELECT revision,sha256 FROM owner_schema_version")
        ).all() != [("0001_owner_schema", baseline)]:
            raise ValueError("User owner baseline identity differs")
        db.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS owner_authority_version (revision text PRIMARY KEY,sha256 text NOT NULL)"
        )
        previous = db.execute(
            text("SELECT revision,sha256 FROM owner_authority_version")
        ).all()
        if previous:
            if previous != [("0002_authority", digest)]:
                raise ValueError("Authority migration identity differs")
            return
        db.exec_driver_sql(ddl)
        db.execute(
            text("INSERT INTO owner_authority_version VALUES (:revision,:digest)"),
            {"revision": "0002_authority", "digest": digest},
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--database-url-file", type=Path, required=True)
    args = p.parse_args()
    engine = create_engine(args.database_url_file.read_text().strip())
    try:
        install(engine)
    finally:
        engine.dispose()
