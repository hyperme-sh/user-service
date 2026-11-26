"""Reconcile the two ordinary memberships for the dedicated Portal TEST account."""

import json
import os
import re
import sys
from uuid import UUID

from sqlalchemy import create_engine, text

from user_service.fixture_bootstrap import identifier
from user_service.fixture_topology import scope
from user_service.startup_github_fixture import GENERATION, ISSUER, install_person, require_test_owner

EMAIL = "portal-bundle-switch@test.hyperme.sh"
SUBJECT = UUID("10963c44-91a2-542b-aa27-c63d7bacd9cb")
DESTINATIONS = (
    ("hyperme.sh", UUID("8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d"), UUID("6e5ea9b8-0a17-56a2-8b33-ef4797ca2b04")),
    ("s3r.ch", UUID("afee9b29-1706-5590-bbbf-e58df8945ac0"), UUID("1a875746-2c03-5675-aa71-ac9130dbd7f8")),
)


def validate(activation, observation):
    expected = {str(tenant): str(org) for _, tenant, org in DESTINATIONS}
    if (set(activation) != {"manifest_sha256", "subjects_sha256", "organizations"}
            or activation["organizations"] != expected
            or any(not re.fullmatch("[0-9a-f]{64}", activation[key])
                   for key in ("manifest_sha256", "subjects_sha256"))):
        raise ValueError("Exactly the declared TEST Portal organizations are required")
    enabled = observation.get("enabled")
    if (type(enabled) is not bool
            or observation != {"issuer": ISSUER, "email": EMAIL, "subject": str(SUBJECT), "enabled": enabled}):
        raise ValueError("The dedicated Portal TEST identity is required")


def provision(engine, activation, observation):
    validate(activation, observation)
    enabled = observation["enabled"]
    with engine.begin() as db:
        db.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
        require_test_owner(db)
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:subject, 0))"),
                   {"subject": str(SUBJECT)})
        scope(db)
        seal = db.execute(text("""
            SELECT generation,manifest_sha256,subjects_sha256
              FROM authority_fixture_generation FOR SHARE
        """)).one()
        if tuple(seal) != (GENERATION, activation["manifest_sha256"], activation["subjects_sha256"]):
            raise ValueError("Installed TEST User generation differs")

        if enabled and install_person(db, None, SUBJECT, SUBJECT, EMAIL, fixture_name="Portal Switch") != SUBJECT:
            raise ValueError("Unexpected Portal TEST person identity")
        for network, tenant, organization in DESTINATIONS:
            profile = identifier(GENERATION, "member", tenant, SUBJECT)
            if enabled and install_person(db, tenant, profile, SUBJECT, EMAIL, fixture_name="Portal Switch") != profile:
                raise ValueError("Unexpected Portal TEST profile identity")

            scope(db, tenant, network)
            params = {"network": network, "tenant": tenant, "organization": organization,
                      "person": SUBJECT, "member": profile}
            if not enabled:
                db.execute(text("""
                    DELETE FROM organization_memberships
                     WHERE tenant_id=:tenant AND organization_id=:organization AND user_id=:member
                       AND role='member' AND NOT can_purchase_leases
                """), params)
                continue
            db.execute(text("""
                SELECT o.id FROM organizations o
                  JOIN tenants t ON t.id=o.tenant_id
                  JOIN authority_tenants a ON a.tenant_id=t.id
                  JOIN authority_networks n ON n.id=a.network_id
                 WHERE o.id=:organization AND t.id=:tenant AND t.is_active AND n.id=:network AND n.enabled
                 FOR SHARE OF o,t,a,n
            """), params).scalar_one()
            if db.scalar(text("""
                SELECT EXISTS(SELECT 1 FROM authority_network_admins WHERE network_id=:network AND user_id=:person)
                    OR EXISTS(SELECT 1 FROM authority_host_owners WHERE tenant_id=:tenant AND user_id=:member)
                    OR EXISTS(SELECT 1 FROM user_group_memberships WHERE tenant_id=:tenant AND user_id=:member)
                    OR EXISTS(SELECT 1 FROM operator_bans WHERE tenant_id=:tenant AND subject_kind='user'
                               AND subject_id IN (:person,:member) AND lifted_at IS NULL)
            """), params):
                raise ValueError("Conflicting authority or active ban for the Portal TEST identity")
            grants = db.execute(text("""
                SELECT organization_id,role,can_purchase_leases,enabled FROM organization_memberships
                 WHERE tenant_id=:tenant AND user_id=:member FOR UPDATE
            """), params).all()
            if grants and grants != [(organization, "member", False, True)]:
                raise ValueError("Unexpected memberships for the Portal TEST identity")
            if not grants:
                db.execute(text("""
                    INSERT INTO organization_memberships(tenant_id,organization_id,user_id,role,can_purchase_leases,enabled)
                    VALUES(:tenant,:organization,:member,'member',false,true)
                """), params)
    return {"subject": str(SUBJECT), "organizations": activation["organizations"]}


def main():
    if os.environ.get("USER_TEST_PORTAL_SWITCH_ENABLED") != "1":
        raise ValueError("Explicit TEST Portal switch configuration required")
    payload = json.loads(sys.stdin.buffer.read(4097))
    if set(payload) != {"activation", "observation"}:
        raise ValueError("Expected the declared identity and active TEST generation")
    engine = create_engine(os.environ["USER_FIXTURE_DATABASE_URL"])
    try:
        print(json.dumps(provision(engine, payload["activation"], payload["observation"])))
    finally:
        engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("User-owned TEST Portal switch provisioning refused") from None
