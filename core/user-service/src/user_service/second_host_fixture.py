"""Adopt the permanent second TEST host owner in an existing fixture generation."""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

from sqlalchemy import create_engine, text

from user_service.fixture_bootstrap import identifier

# Exact input and output of infra #701. Neither manifest is received from an API.
BEFORE = "1b71954639d6c407a3760664239dc2fe6f994269a161564e57a413186a22f56f"
AFTER = "78d5697e99687b238ac1f59d416571a03688ee5c4e398b21181b73e3bd5b84a3"


def apply(engine, before, after):
    if (hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest()) != (BEFORE, AFTER):
        raise ValueError("Expected the canonical second host fixture transition")
    manifest = json.loads(after)
    generation = manifest["generation"]
    host = next(h for h in manifest["hosts"] if h["name"] == "TEST-OTHER-ORG-01")
    account = next(a for a in manifest["accounts"] if a["key"] == host["owner"])
    org = next(o for o in manifest["organizations"] if o["key"] == host["organization"])
    tenant = uuid.UUID(next(t["id"] for t in manifest["tenants"] if t["key"] == org["tenant"]))
    user = identifier(generation, "member", tenant, account["id"])
    group = identifier(generation, "group", tenant, "host")
    params = dict(tenant=tenant, org=uuid.UUID(org["id"]), user=user, subject=account["id"],
                  email=account["email"], group=group, generation=generation,
                  membership=identifier(generation, "group-member", tenant, user, "host"))
    with engine.begin() as db:
        db.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
        authorized = db.scalar(text("""
            SELECT current_database()='controlplane_test_v1' AND current_schema()='user_owner'
              AND current_user='reset_v1_user_migrator' AND n.nspowner=r.oid
              AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
            FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema()
            WHERE r.rolname=current_user
        """))
        if authorized is not True:
            raise ValueError("Canonical TEST User schema owner required")
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
        installed = db.execute(text("SELECT manifest_sha256 FROM authority_fixture_generation "
                                    "WHERE generation=:generation FOR UPDATE"), params).scalar_one()
        if installed not in (BEFORE, AFTER):
            raise ValueError("Unexpected installed fixture generation")
        db.execute(text("SELECT set_config('app.current_tenant_id',CAST(:tenant AS text),true)"), params)
        member = db.execute(text("""
            SELECT u.id FROM users u JOIN organization_memberships m
              ON m.user_id=u.id AND m.tenant_id=u.tenant_id
            WHERE u.id=:user AND u.tenant_id=:tenant AND u.keycloak_sub=:subject AND u.email=:email
              AND u.is_active AND m.organization_id=:org AND m.enabled AND m.can_purchase_leases
              AND m.role='member' FOR UPDATE OF u,m
        """), params).scalar_one()
        db.execute(text("SELECT id FROM groups WHERE id=:group AND tenant_id=:tenant AND name='host' FOR SHARE"), params).scalar_one()
        owner_query = text("SELECT organization_id FROM authority_host_owners WHERE tenant_id=:tenant AND user_id=:user")
        group_query = text("SELECT id FROM user_group_memberships WHERE tenant_id=:tenant AND user_id=:user AND group_id=:group")
        if installed == BEFORE:
            if db.scalar(owner_query, params) or db.scalar(group_query, params):
                raise ValueError("Unexpected pre-existing host authority")
            db.execute(text("INSERT INTO authority_host_owners(tenant_id,organization_id,user_id) VALUES (:tenant,:org,:user)"), params)
            db.execute(text("INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id) VALUES (:membership,:tenant,:user,:group)"), params)
            db.execute(text("UPDATE authority_fixture_generation SET manifest_sha256=:after WHERE generation=:generation"),
                       {**params, "after": AFTER})
        if db.scalar(owner_query, params) != params["org"] or db.scalar(group_query, params) != params["membership"]:
            raise ValueError("Installed host owner differs from fixture")
    return dict(generation=generation, predecessor_sha256=BEFORE, successor_sha256=AFTER,
                tenant_id=str(tenant), organization_id=str(params["org"]), user_id=str(member))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("previous", "desired", "database-url-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    engine = create_engine(args.database_url_file.read_text().strip())
    try:
        print(json.dumps(apply(engine, args.previous.read_bytes(), args.desired.read_bytes())))
    finally:
        engine.dispose()
