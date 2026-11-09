"""Journaled, owner-only additive TEST topology transition; never bootstrap/reseed."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid

from sqlalchemy import create_engine, inspect, text

from user_service.fixture_bootstrap import S3RCH_TEST_TENANT as ADDITION
from user_service.adopt_test_tenant import _install



def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plan(previous, desired):
    before, after = json.loads(previous), json.loads(desired)
    if (before.get("schema_version") != 1 or before.get("environment") != "test"
            or before.get("generation") != "test-reset-v1"
            or {k:v for k,v in before.items() if k != "tenants"} != {k:v for k,v in after.items() if k != "tenants"}
            or len(before["tenants"]) != 2 or {t["key"] for t in before["tenants"]} != {"active", "isolation"}
            or len(after["tenants"]) != 3
            or sorted(after["tenants"], key=lambda t:t["key"]) != sorted([*before["tenants"], ADDITION], key=lambda t:t["key"])):
        raise ValueError("Only the declared s3r.ch tenant addition is supported")
    return {"generation": before["generation"], "predecessor_sha256": sha(previous),
            "successor_sha256": sha(desired), "addition": ADDITION}


def scope(db, tenant=None, network=None):
    db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true),set_config('app.current_network_id',:network,true)"),
               {"tenant": str(tenant) if tenant else "", "network": network or ""})


def topology(db, manifest):
    expected = manifest["tenants"]
    actual = db.execute(text("SELECT id::text,name,is_active FROM tenants ORDER BY id FOR SHARE")).all()
    if actual != sorted([(t["id"],t["name"],t["active"]) for t in expected]):
        raise ValueError("Unexpected live tenant topology")
    for tenant in expected:
        scope(db, tenant["id"])
        rows = db.execute(text("SELECT tenant_id::text,network_id FROM authority_tenants FOR SHARE")).all()
        if rows != [(tenant["id"],tenant["network"])]:
            raise ValueError("Live tenant network binding differs")


def protected(db, manifest):
    """Observe unchanged identity/grant rows under each explicit RLS scope."""
    values = []
    for network in manifest["networks"]:
        scope(db, network=network["id"])
        for table in ("authority_networks", "authority_network_admins", "authority_fixture_accounts", "users"):
            rows = db.execute(text(f"SELECT row_to_json(t)::text FROM {table} t FOR SHARE")).scalars().all()
            values.extend((network["id"],table,json.dumps(json.loads(r),sort_keys=True)) for r in rows)
    for tenant in manifest["tenants"]:
        scope(db, tenant["id"])
        for table in ("users", "roles", "groups", "organizations", "organization_memberships", "user_group_memberships", "authority_host_owners"):
            rows = db.execute(text(f"SELECT row_to_json(t)::text FROM {table} t FOR SHARE")).scalars().all()
            values.extend((tenant["id"],table,json.dumps(json.loads(r),sort_keys=True)) for r in rows)
    return sha(json.dumps(sorted(values),separators=(",",":")).encode())


def inserted_metadata(db):
    """Fingerprint every column of the rows rollback would delete."""
    scope(db, ADDITION["id"], ADDITION["network"])
    rows = []
    for table in ("tenants", "authority_tenants", "roles", "groups", "service_tenants"):
        key = "id" if table == "tenants" else "tenant_id"
        statement = text(f"SELECT to_jsonb(t)::text FROM {table} t WHERE {key}=:tenant")
        for value in db.scalars(statement, {"tenant": uuid.UUID(ADDITION["id"])}):
            rows.append((table, value))
    return sha(json.dumps(sorted(rows)).encode())


def transition(engine, previous, desired, *, operation_id, source_sha, action="apply"):
    proposal = plan(previous, desired)
    operation_id = str(uuid.UUID(operation_id))
    if re.fullmatch("[a-f0-9]{40}", source_sha) is None or action not in ("apply", "rollback"):
        raise ValueError("Exact owner source and supported action required")
    before, after = json.loads(previous), json.loads(desired)
    with engine.begin() as db:
        # Rollback checks each table after locking it and must see intervening commits.
        isolation = "READ COMMITTED" if action == "rollback" else "SERIALIZABLE"
        db.execute(text(f"SET TRANSACTION ISOLATION LEVEL {isolation}"))
        db.execute(text("SET LOCAL TIME ZONE 'UTC'"))
        flags = db.execute(text("""SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication,
            n.nspowner=r.oid AS owns_schema,n.nspname FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema()
            WHERE r.rolname=current_user""")).mappings().one()
        if (any(flags[k] for k in ("rolsuper","rolbypassrls","rolcreaterole","rolcreatedb","rolreplication"))
                or not flags["owns_schema"] or flags["nspname"] == "public"):
            raise ValueError("Nonprivileged User schema owner required")
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
        scope(db)
        generation = db.execute(text("SELECT generation,manifest_sha256,subjects_sha256,source_sha FROM authority_fixture_generation FOR UPDATE")).mappings().all()
        if len(generation) != 1 or generation[0]["generation"] != proposal["generation"]:
            raise ValueError("Exact existing fixture generation required")
        generation = generation[0]
        db.execute(text("""CREATE TABLE IF NOT EXISTS authority_fixture_transitions(
            operation_id uuid PRIMARY KEY, predecessor_sha256 text NOT NULL, successor_sha256 text NOT NULL,
            source_sha text NOT NULL, state text NOT NULL CHECK(state IN ('applied','rolled-back')), receipt jsonb NOT NULL)"""))
        journal = db.execute(text("SELECT * FROM authority_fixture_transitions WHERE operation_id=:id FOR UPDATE"),{"id":operation_id}).mappings().one_or_none()
        if journal and any(journal[k] != v for k,v in {"predecessor_sha256":proposal["predecessor_sha256"],"successor_sha256":proposal["successor_sha256"],"source_sha":source_sha}.items()):
            raise ValueError("Operation identity conflicts with retained journal")
        if journal and ((action == "apply" and journal["state"] == "applied") or (action == "rollback" and journal["state"] == "rolled-back")):
            expected = after if action == "apply" else before
            if generation["manifest_sha256"] != sha(desired if action == "apply" else previous):
                raise ValueError("Generation changed after transition")
            topology(db, expected)
            return journal["receipt"]
        if action == "apply":
            if journal or generation["manifest_sha256"] != proposal["predecessor_sha256"]:
                raise ValueError("Expected predecessor generation; no reseed or repair")
            topology(db, before)
            fingerprint = protected(db, before)
            if db.scalar(text("SELECT EXISTS(SELECT 1 FROM service_tenants WHERE tenant_id=:id)"),{"id":uuid.UUID(ADDITION["id"])}):
                raise ValueError("Undeclared tenant already has owner state")
            _install(db, proposal["generation"], sha(previous), sha(desired), uuid.UUID(ADDITION["id"]))
            topology(db, after)
            if protected(db, before) != fingerprint:
                raise ValueError("Existing identities or grants changed")
            receipt = {**proposal,"operation_id":operation_id,"source_sha":source_sha,
                       "predecessor_source_sha":generation["source_sha"],"subjects_sha256":generation["subjects_sha256"],
                       "inserted_metadata_sha256":inserted_metadata(db),
                       "protected_sha256":fingerprint,"state":"applied","runtime_accepted":False}
            db.execute(text("INSERT INTO authority_fixture_transitions VALUES(:id,:before,:after,:source,'applied',CAST(:receipt AS jsonb))"),
                       {"id":operation_id,"before":sha(previous),"after":sha(desired),"source":source_sha,"receipt":json.dumps(receipt)})
            target_sha, target_source = sha(desired), generation["source_sha"]
        else:
            if not journal or journal["state"] != "applied" or generation["manifest_sha256"] != sha(desired) or generation["source_sha"] != journal["receipt"]["predecessor_source_sha"]:
                raise ValueError("Exact applied transition required for rollback")
            topology(db, after)
            scope(db, ADDITION["id"])
            # Refuse once any owner table has tenant data. Never erase new business
            # state to make a rollback succeed, including tables added later.
            inspector = inspect(db)
            quote = db.dialect.identifier_preparer.quote
            for table in inspector.get_table_names(schema=flags["nspname"]):
                if table in ("authority_tenants", "roles", "groups", "service_tenants"):continue
                if "tenant_id" in {c["name"] for c in inspector.get_columns(table,schema=flags["nspname"])}:
                    db.execute(text(f"LOCK TABLE {quote(table)} IN SHARE ROW EXCLUSIVE MODE"))
                    if db.scalar(text(f"SELECT EXISTS(SELECT 1 FROM {quote(table)} WHERE tenant_id=:id)"),{"id":uuid.UUID(ADDITION["id"])}):
                        raise ValueError("New tenant is in use; rollback refused: "+table)
            for table in ("roles", "groups", "service_tenants"):
                db.execute(text(f"LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE"))
            if inserted_metadata(db) != journal["receipt"].get("inserted_metadata_sha256"):
                raise ValueError("New tenant metadata changed; rollback refused")
            db.execute(text("DELETE FROM groups WHERE tenant_id=:id"),{"id":uuid.UUID(ADDITION["id"])})
            db.execute(text("DELETE FROM roles WHERE tenant_id=:id"),{"id":uuid.UUID(ADDITION["id"])})
            db.execute(text("DELETE FROM authority_tenants WHERE tenant_id=:id"),{"id":uuid.UUID(ADDITION["id"])})
            db.execute(text("DELETE FROM service_tenants WHERE tenant_id=:id"),{"id":uuid.UUID(ADDITION["id"])})
            db.execute(text("DELETE FROM tenants WHERE id=:id"),{"id":uuid.UUID(ADDITION["id"])})
            topology(db, before)
            receipt = {**journal["receipt"],"state":"rolled-back"}
            db.execute(text("UPDATE authority_fixture_transitions SET state='rolled-back',receipt=CAST(:receipt AS jsonb) WHERE operation_id=:id"),{"id":operation_id,"receipt":json.dumps(receipt)})
            target_sha, target_source = sha(previous), receipt["predecessor_source_sha"]
        db.execute(text("UPDATE authority_fixture_generation SET manifest_sha256=:manifest,source_sha=:source WHERE generation=:generation"),
                   {"manifest":target_sha,"source":target_source,"generation":proposal["generation"]})
        return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan","apply","rollback"))
    for name in ("previous","desired"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--operation-id");p.add_argument("--source-sha");p.add_argument("--database-url-file",type=Path)
    args=p.parse_args();previous=args.previous.read_bytes();desired=args.desired.read_bytes()
    if args.action=="plan":result=plan(previous,desired)
    else:
        if not all((args.operation_id,args.source_sha,args.database_url_file)):p.error("Owner operation/source/database required")
        engine=create_engine(args.database_url_file.read_text().strip())
        try:result=transition(engine,previous,desired,operation_id=args.operation_id,source_sha=args.source_sha,action=args.action)
        finally:engine.dispose()
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    try:main()
    except Exception:raise SystemExit("User-owned TEST topology transition refused; retain private journal and diagnostics") from None
