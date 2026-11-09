"""Add the configured s3r.ch tenant to an existing canonical TEST generation."""

import hashlib
import json
import uuid

from sqlalchemy import text

from user_service.fixture_bootstrap import S3RCH_TEST_TENANT, insert_tenant


def adopt(engine, previous_bytes, candidate_bytes):
    previous = json.loads(previous_bytes)
    candidate = json.loads(candidate_bytes)
    generation = "test-reset-v1"
    if (previous.get("generation") != generation or previous.get("environment") != "test"
            or {row["key"] for row in previous["tenants"]} != {"active", "isolation"}
            or candidate != {**previous, "tenants": [*previous["tenants"], S3RCH_TEST_TENANT]}):
        raise ValueError("Expected only the declared s3r.ch TEST tenant addition")
    before = hashlib.sha256(previous_bytes).hexdigest()
    after = hashlib.sha256(candidate_bytes).hexdigest()
    tenant = uuid.UUID(S3RCH_TEST_TENANT["id"])
    with engine.begin() as db:
        authorized = db.scalar(text("""
            SELECT current_database()='controlplane_test_v1' AND current_schema()='user_owner'
                AND current_user='reset_v1_user_migrator' AND n.nspowner=r.oid
                AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
            FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema()
            WHERE r.rolname=current_user
        """))
        if authorized is not True:
            raise ValueError("Exact canonical TEST User schema owner required")
        _install(db, generation, before, after, tenant)
    return {"generation": generation, "tenant_id": str(tenant), "manifest_sha256": after}


def _install(db, generation, before, after, tenant):
    db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
    installed = db.execute(text("""
        SELECT manifest_sha256 FROM authority_fixture_generation
        WHERE generation=:generation FOR UPDATE
    """), {"generation": generation}).scalar_one()
    if installed not in (before, after):
        raise ValueError("Installed generation differs from both manifests")
    db.execute(text("""
        SELECT set_config('app.current_network_id','s3r.ch',true),
               set_config('app.current_tenant_id',:tenant,true)
    """), {"tenant": str(tenant)})
    if db.scalar(text("SELECT id FROM authority_networks WHERE id='s3r.ch'")) != "s3r.ch":
        raise ValueError("Configured s3r.ch network missing")
    if installed == before:
        insert_tenant(db, generation, S3RCH_TEST_TENANT, tenant)
        db.execute(text("""
            UPDATE authority_fixture_generation SET manifest_sha256=:after
            WHERE generation=:generation AND manifest_sha256=:before
        """), {"after": after, "before": before, "generation": generation})
    observed = db.execute(text("""
        SELECT t.name,t.is_active,a.network_id FROM tenants t
        JOIN authority_tenants a ON a.tenant_id=t.id WHERE t.id=:tenant
    """), {"tenant": tenant}).one()
    if tuple(observed) != ("s3r.ch TEST", True, "s3r.ch"):
        raise ValueError("Installed s3r.ch tenant binding differs")


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    from sqlalchemy import create_engine

    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("previous-manifest", "candidate-manifest", "database-url-file"):
        parser.add_argument("--" + argument, type=Path, required=True)
    args = parser.parse_args()
    engine = create_engine(args.database_url_file.read_text().strip())
    try:
        result = adopt(engine, args.previous_manifest.read_bytes(), args.candidate_manifest.read_bytes())
        print(json.dumps(result, sort_keys=True))
    finally:
        engine.dispose()
