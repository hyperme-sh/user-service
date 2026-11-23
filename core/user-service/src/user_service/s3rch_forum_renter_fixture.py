"""Install the declared s3r.ch TEST renter in the retained User authority."""

import json
import os
import re
import sys
from uuid import UUID

from sqlalchemy import create_engine, text

from user_service.fixture_bootstrap import identifier
from user_service.fixture_topology import scope
from user_service.s3rch_forum_host_fixture import NETWORK, ORG, TENANT, ensure_organization
from user_service.startup_github_fixture import GENERATION, ISSUER, install_person, require_test_owner

ACCOUNT = "s3rch-forum-renter"
SUBJECT = UUID("d2b1afb6-3046-5409-98ae-91daf8f3f1f8")
EMAIL = f"{ACCOUNT}@test.s3r.ch"


def validate(activation, observation):
    if (
        set(activation) != {"manifest_sha256", "subjects_sha256", "tenant", "organization"}
        or (activation["tenant"], activation["organization"]) != (str(TENANT), str(ORG))
        or any(not re.fullmatch("[a-f0-9]{64}", activation[key])
               for key in ("manifest_sha256", "subjects_sha256"))
        or observation != {"issuer": ISSUER, "subject": str(SUBJECT), "email": EMAIL,
                           "tenant": str(TENANT), "enabled": True}
        or observation["enabled"] is not True
    ):
        raise ValueError("Exact s3r.ch TEST renter observation required")


def provision(engine, activation, observation):
    validate(activation, observation)
    profile = identifier(GENERATION, "member", TENANT, SUBJECT)
    renter_group = identifier(GENERATION, "group", TENANT, "renter")
    group_membership = identifier(GENERATION, "group-member", TENANT, profile, "renter")
    params = {"generation": GENERATION, "tenant": TENANT, "organization": ORG, "network": NETWORK,
              "subject": SUBJECT, "actor": ACCOUNT, "profile": profile,
              "group": renter_group, "membership": group_membership}
    with engine.begin() as db:
        db.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
        require_test_owner(db)
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
        scope(db)
        seal = db.execute(text("""
            SELECT generation,manifest_sha256,subjects_sha256
              FROM authority_fixture_generation FOR SHARE
        """)).one()
        if tuple(seal) != (GENERATION, activation["manifest_sha256"], activation["subjects_sha256"]):
            raise ValueError("Installed TEST User generation differs")
        scope(db, TENANT, NETWORK)
        db.execute(text("""
            SELECT t.id FROM tenants t
              JOIN authority_tenants a ON a.tenant_id=t.id
              JOIN authority_networks n ON n.id=a.network_id
             WHERE t.id=:tenant AND t.is_active AND n.id=:network AND n.enabled
             FOR SHARE OF t,a,n
        """), params).scalar_one()
        db.execute(text("""
            SELECT id FROM groups WHERE id=:group AND tenant_id=:tenant AND name='renter' FOR SHARE
        """), params).scalar_one()
        ensure_organization(db, enabled=True)
        scope(db, network=NETWORK)
        declared = db.execute(text("""
            SELECT user_id,account_key,tenant_context FROM authority_fixture_accounts
             WHERE user_id=:subject OR account_key=:actor FOR UPDATE
        """), params).one_or_none()
        if declared is not None and tuple(declared) != (SUBJECT, ACCOUNT, TENANT):
            raise ValueError("Existing TEST renter declaration differs")
        if db.scalar(text("SELECT EXISTS(SELECT 1 FROM authority_network_admins WHERE user_id=:subject)"), params):
            raise ValueError("Conflicting TEST network authority")

        person = install_person(db, None, SUBJECT, SUBJECT, EMAIL, fixture_name="Forum Renter")
        member = install_person(db, TENANT, profile, SUBJECT, EMAIL, fixture_name="Forum Renter")
        if (person, member) != (SUBJECT, profile):
            raise ValueError("Existing TEST renter identity differs")
        if db.scalar(text("""
            SELECT EXISTS(SELECT 1 FROM authority_host_owners WHERE tenant_id=:tenant AND user_id=:profile)
                OR EXISTS(SELECT 1 FROM operator_bans WHERE tenant_id=:tenant AND subject_kind='user'
                           AND subject_id IN (:subject,:profile) AND lifted_at IS NULL)
        """), params):
            raise ValueError("TEST renter has conflicting authority or an active ban")
        grants = db.execute(text("""
            SELECT organization_id,role,can_purchase_leases,enabled
              FROM organization_memberships WHERE tenant_id=:tenant AND user_id=:profile FOR UPDATE
        """), params).all()
        groups = db.execute(text("""
            SELECT id,group_id FROM user_group_memberships WHERE tenant_id=:tenant AND user_id=:profile FOR UPDATE
        """), params).all()
        if declared is None:
            if grants or groups:
                raise ValueError("TEST renter has existing grants outside this fixture")
            db.execute(text("""
                INSERT INTO organization_memberships(tenant_id,organization_id,user_id,role,can_purchase_leases,enabled)
                VALUES(:tenant,:organization,:profile,'member',true,true)
            """), params)
            db.execute(text("""
                INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id)
                VALUES(:membership,:tenant,:profile,:group)
            """), params)
            scope(db, network=NETWORK)
            db.execute(text("""
                INSERT INTO authority_fixture_accounts(user_id,account_key,network_id,tenant_context)
                VALUES(:subject,:actor,:network,:tenant)
            """), params)
        elif grants != [(ORG, "member", True, True)] or groups != [(group_membership, renter_group)]:
            raise ValueError("Existing TEST renter grants differ")
    return {"state": "existing" if declared else "provisioned", "tenant": str(TENANT),
            "organization": str(ORG), "user_id": str(SUBJECT), "subject": str(SUBJECT)}


def main():
    payload = json.loads(sys.stdin.buffer.read(4097))
    if set(payload) != {"activation", "observation"} or os.environ.get("USER_TEST_FORUM_RENTER_ENABLED") != "1":
        raise ValueError("Explicit TEST renter configuration required")
    engine = create_engine(os.environ["USER_FIXTURE_DATABASE_URL"])
    try:
        print(json.dumps(provision(engine, payload["activation"], payload["observation"])))
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("User-owned TEST forum renter provisioning refused") from None
