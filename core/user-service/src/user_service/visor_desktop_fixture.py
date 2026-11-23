"""Add an explicitly declared member to the canonical TEST User owner."""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

from sqlalchemy import create_engine, text

from user_service.fixture_bootstrap import identifier, validate

ISSUER = "https://auth.test.hyperme.sh/realms/controlplane"
GENERATION = "test-reset-v1"
RENTER = {
    "key": "visor-desktop-renter",
    "id": "d613a331-4a01-4b83-9a3f-658a6a8c24eb",
    "email": "visor-desktop-renter@test.hyperme.sh",
    "enabled": True,
    "grants": [{"scope": "organization", "target": "primary", "role": "member"}],
    "can_purchase_leases": True,
    "host_owner": False,
    "password_secret": "test-fixture-visor-desktop-renter-password",
    "tenant_context": "active",
}


PORTAL_MEMBER = {
    **RENTER,
    "key": "portal-device-transfer-member",
    "id": "c92fc0dd-c922-5c71-88da-bd91b38d14a4",
    "email": "portal-device-transfer-member@test.hyperme.sh",
    "password_secret": "test-fixture-portal-device-transfer-member-password",
    "can_purchase_leases": False,
}
FIXTURES = {row["key"]: row for row in (RENTER, PORTAL_MEMBER)}


def plan(previous, desired, previous_bindings, desired_bindings, *, fixture=RENTER["key"]):
    member = FIXTURES.get(fixture)
    if member is None:
        raise ValueError("Exact TEST fixture required")
    before, after, old_subjects, new_subjects = map(
        json.loads, (previous, desired, previous_bindings, desired_bindings)
    )
    validate(before, old_subjects, generation=GENERATION, issuer=ISSUER)
    _, tenants, orgs, _, _ = validate(after, new_subjects, generation=GENERATION, issuer=ISSUER)
    old_hash, new_hash, old_subject_hash, new_subject_hash = (
        hashlib.sha256(raw).hexdigest()
        for raw in (previous, desired, previous_bindings, desired_bindings)
    )
    binding = {"account_key": member["key"], "id": member["id"],
               "email": member["email"], "enabled": True}
    if (old_subjects.get("manifest_sha256") != old_hash
            or after != {**before, "accounts": [*before["accounts"], member]}
            or new_subjects != {**old_subjects, "manifest_sha256": new_hash,
                                "subjects": [*old_subjects["subjects"], binding]}
            or orgs["primary"]["tenant"] != "active" or tenants["active"]["active"] is not True):
        raise ValueError("Only the exact declared member addition is supported")
    tenant = uuid.UUID(tenants["active"]["id"])
    subject = uuid.UUID(member["id"])
    profile = identifier(GENERATION, "member", tenant, subject)
    return dict(generation=GENERATION, old_hash=old_hash, new_hash=new_hash,
                old_subject_hash=old_subject_hash, new_subject_hash=new_subject_hash,
                tenant=tenant, network=tenants["active"]["network"], org=uuid.UUID(orgs["primary"]["id"]),
                subject=subject, subject_text=str(subject), profile=profile, email=member["email"], key=member["key"],
                can_purchase_leases=member["can_purchase_leases"],
                role=identifier(GENERATION, "role", tenant, "user"),
                group=identifier(GENERATION, "group", tenant, "renter"),
                membership=identifier(GENERATION, "group-member", tenant, profile, "renter"))


def require_owner(db):
    authorized = db.scalar(text("""
        SELECT current_database()='controlplane_test_v1' AND current_schema()='user_owner'
          AND current_user='reset_v1_user_migrator' AND n.nspowner=r.oid
          AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
        FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema()
        WHERE r.rolname=current_user
    """))
    if authorized is not True:
        raise ValueError("Canonical TEST User schema owner required")


def apply(engine, previous, desired, previous_bindings, desired_bindings, *, fixture=RENTER["key"]):
    args = plan(previous, desired, previous_bindings, desired_bindings, fixture=fixture)
    before = (args["old_hash"], args["old_subject_hash"])
    after = (args["new_hash"], args["new_subject_hash"])
    with engine.begin() as db:
        db.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
        require_owner(db)
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
        installed = tuple(db.execute(text("""
            SELECT manifest_sha256, subjects_sha256 FROM authority_fixture_generation
            WHERE generation=:generation FOR UPDATE
        """), args).one())
        if installed not in (before, after):
            raise ValueError("Unexpected installed TEST fixture binding")
        db.execute(text("SELECT set_config('app.current_network_id',:network,true), "
                        "set_config('app.current_tenant_id','',true)"), args)
        if installed == before:
            db.execute(text("""
                INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active)
                VALUES(:subject,NULL,:subject_text,:email,:key,'Fixture','unspecified',true)
            """), args)
            db.execute(text("INSERT INTO authority_fixture_accounts VALUES(:subject,:key,:network,:tenant)"), args)
        db.execute(text("""
            SELECT a.user_id FROM authority_fixture_accounts a JOIN users u ON u.id=a.user_id
            WHERE a.user_id=:subject AND a.account_key=:key AND a.network_id=:network
              AND a.tenant_context=:tenant AND u.tenant_id IS NULL AND u.keycloak_sub=:subject_text
              AND u.email=:email AND u.is_active
        """), args).scalar_one()
        db.execute(text("SELECT set_config('app.current_tenant_id',CAST(:tenant AS text),true), "
                        "set_config('app.current_network_id','',true)"), args)
        if args["can_purchase_leases"]:
            db.execute(text("SELECT id FROM groups WHERE id=:group AND tenant_id=:tenant AND name='renter'"), args).scalar_one()
        if installed == before:
            db.execute(text("""
                INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id)
                VALUES(:profile,:tenant,:subject_text,:email,:key,'Fixture','unspecified',true,:role)
            """), args)
            db.execute(text("INSERT INTO organization_memberships VALUES(:tenant,:org,:profile,'member',:can_purchase_leases,true)"), args)
            if args["can_purchase_leases"]:
                db.execute(text("INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id) "
                                "VALUES(:membership,:tenant,:profile,:group)"), args)
            db.execute(text("""
                UPDATE authority_fixture_generation SET manifest_sha256=:new_hash, subjects_sha256=:new_subject_hash
                WHERE generation=:generation
            """), args)
        db.execute(text("""
            SELECT u.id FROM users u JOIN organization_memberships m
              ON m.user_id=u.id AND m.tenant_id=u.tenant_id
            WHERE u.id=:profile AND u.tenant_id=:tenant AND u.keycloak_sub=:subject_text AND u.email=:email
              AND u.role_id=:role AND u.is_active AND m.organization_id=:org
              AND m.enabled AND m.can_purchase_leases=:can_purchase_leases AND m.role='member'
        """), args).scalar_one()
        groups = db.execute(text("""
            SELECT id, group_id FROM user_group_memberships
            WHERE tenant_id=:tenant AND user_id=:profile
              AND (NOT :can_purchase_leases OR id=:membership)
        """), args).all()
        expected_groups = [(args["membership"], args["group"])] if args["can_purchase_leases"] else []
        if groups != expected_groups:
            raise ValueError("Unexpected TEST fixture groups")
    return dict(generation=GENERATION, subject=str(args["subject"]), user_id=str(args["profile"]),
                predecessor_sha256=before[0], successor_sha256=after[0], subjects_sha256=after[1],
                changed=installed == before)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("previous", "desired", "previous-bindings", "desired-bindings", "database-url-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--fixture", choices=FIXTURES, default=RENTER["key"])
    options = parser.parse_args()
    engine = create_engine(options.database_url_file.read_text().strip())
    try:
        print(json.dumps(apply(engine, options.previous.read_bytes(), options.desired.read_bytes(),
                               options.previous_bindings.read_bytes(), options.desired_bindings.read_bytes(), fixture=options.fixture)))
    finally:
        engine.dispose()
