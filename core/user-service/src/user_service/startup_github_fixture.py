"""Install the declared, unprivileged GitHub member in the sealed TEST database."""

import argparse
import json
import os
from pathlib import Path
import re
import uuid

from sqlalchemy import create_engine, text

from user_service.fixture_bootstrap import identifier
from user_service.fixture_topology import scope


ISSUER = "https://auth.test.hyperme.sh/realms/controlplane"
GENERATION = "test-reset-v1"


def declaration(activation, observation):
    if (set(activation) != {"manifest_sha256", "subjects_sha256", "tenant_id"}
            or any(not re.fullmatch(r"[a-f0-9]{64}", activation[key])
                   for key in ("manifest_sha256", "subjects_sha256"))
            or set(observation) != {"issuer", "provider", "subject", "email", "upstream_subject", "enabled"}
            or observation["issuer"] != ISSUER or observation["provider"] != "github"
            or observation["enabled"] is not True
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,38}@github\.com", observation["email"])
            or not re.fullmatch(r"[1-9][0-9]*", observation["upstream_subject"])):
        raise ValueError("Exact staged TEST GitHub observation required")
    subject = uuid.UUID(observation["subject"])
    tenant = uuid.UUID(activation["tenant_id"])
    if str(subject) != observation["subject"] or str(tenant) != activation["tenant_id"]:
        raise ValueError("Canonical broker and tenant IDs required")
    return subject, tenant


def provision(engine, activation, observation):
    subject, tenant = declaration(activation, observation)
    profile = identifier(GENERATION, "member", tenant, subject)
    with engine.begin() as db:
        require_test_owner(db)
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:subject,0))"),
            {"subject": str(subject)},
        )
        scope(db)
        seal = db.execute(text("""
            SELECT generation,manifest_sha256,subjects_sha256
              FROM authority_fixture_generation FOR SHARE
        """)).one()
        if tuple(seal) != (GENERATION, activation["manifest_sha256"], activation["subjects_sha256"]):
            raise ValueError("Installed TEST User generation differs")
        scope(db, tenant, "hyperme.sh")
        if not db.scalar(text("""
            SELECT EXISTS(
                SELECT 1 FROM tenants t
                  JOIN authority_tenants a ON a.tenant_id=t.id
                  JOIN authority_networks n ON n.id=a.network_id
                 WHERE t.id=:tenant AND t.is_active AND n.id='hyperme.sh' AND n.enabled
            )
        """), {"tenant": tenant}):
            raise ValueError("Declared TEST tenant is unavailable")
        scope(db, network="hyperme.sh")
        if db.scalar(text("""
            SELECT EXISTS(
                SELECT 1 FROM authority_network_admins a
                  JOIN users u ON u.id=a.user_id
                 WHERE a.network_id='hyperme.sh' AND u.keycloak_sub=:subject
            )
        """), {"subject": str(subject)}):
            raise ValueError("GitHub member has conflicting network authority")
        person = install_person(db, None, subject, subject, observation["email"])
        member = install_person(db, tenant, profile, subject, observation["email"])
        if db.scalar(text("""
            SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE tenant_id=:tenant AND user_id=:member)
                OR EXISTS(SELECT 1 FROM user_group_memberships WHERE tenant_id=:tenant AND user_id=:member)
                OR EXISTS(SELECT 1 FROM operator_bans WHERE tenant_id=:tenant AND subject_kind='user'
                           AND subject_id IN (:person,:member) AND lifted_at IS NULL)
        """), {"tenant": tenant, "person": person, "member": member}):
            raise ValueError("GitHub member has conflicting grants or an active ban")
        return {"person_id": str(person), "member_id": str(member), "status": "provisioned"}


def require_test_owner(db):
    flags = db.execute(text("""
        SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication,
               n.nspowner=r.oid,current_database()
          FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema()
         WHERE r.rolname=current_user AND n.nspname='user_owner'
    """)).one_or_none()
    if flags is None or any(flags[:5]) or flags[5:] != (True, "controlplane_test_v1"):
        raise ValueError("Nonprivileged TEST User schema owner required")


def install_person(db, tenant, user, subject, email):
    scope(db, tenant)
    params = {"tenant": tenant, "user": user, "subject": str(subject), "email": email, "issuer": ISSUER}
    rows = db.execute(text("""
        SELECT id,keycloak_sub,email,is_active,deleted_at,role_id,password,sso_provider_id
          FROM users
         WHERE tenant_id IS NOT DISTINCT FROM CAST(:tenant AS uuid)
           AND (id=:user OR keycloak_sub=:subject OR lower(email)=:email)
         FOR UPDATE
    """), params).all()
    if rows:
        if len(rows) != 1:
            raise ValueError("Conflicting TEST GitHub profile")
        row = rows[0]
        if (row.keycloak_sub != str(subject) or row.email.lower() != email or not row.is_active
                or row.deleted_at or row.role_id or row.password or row.sso_provider_id != ISSUER):
            raise ValueError("Existing TEST GitHub profile differs")
        return row.id
    return db.scalar(text("""
        INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,sso_provider_id)
        VALUES(:user,:tenant,:subject,:email,'TEST','GitHub','unspecified',true,:issuer)
        RETURNING id
    """), params)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("USER_TEST_GITHUB_MEMBER_ENABLED") != "1":
        raise ValueError("Explicit TEST fixture deployment required")
    value = json.loads(args.input.read_bytes())
    engine = create_engine(os.environ["USER_FIXTURE_DATABASE_URL"])
    try:
        print(json.dumps(provision(engine, value["activation"], value["broker"])))
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("User-owned TEST GitHub member provisioning refused") from None
