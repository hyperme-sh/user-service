"""Provision the declared s3r.ch TEST Host owner from a verified IdP observation."""

import json
import os
import re
import sys
from uuid import UUID

from sqlalchemy import create_engine, text

from user_service.fixture_bootstrap import identifier
from user_service.fixture_topology import scope
from user_service.startup_github_fixture import (
    GENERATION,
    ISSUER,
    install_person,
    require_test_owner,
)

NETWORK = "s3r.ch"
TENANT = UUID("afee9b29-1706-5590-bbbf-e58df8945ac0")
ORG = UUID("1a875746-2c03-5675-aa71-ac9130dbd7f8")
ORG_NAME = "s3r.ch primary TEST organization"
SUBJECT = UUID("7595d138-db52-51ba-93de-2bf919e3d337")
ACCOUNT = "s3rch-forum-host-owner"
EMAIL = "s3rch-forum-host-owner@test.s3r.ch"


def validate(activation, observed, *, enabled=True):
    fields = {"manifest_sha256", "subjects_sha256", "tenant", "organization"}
    if (
        set(activation) != fields
        or (activation["tenant"], activation["organization"]) != (str(TENANT), str(ORG))
        or any(not re.fullmatch(r"[a-f0-9]{64}", activation[key])
               for key in ("manifest_sha256", "subjects_sha256"))
        or observed != {"issuer": ISSUER, "subject": str(SUBJECT), "email": EMAIL,
                        "tenant": str(TENANT), "enabled": enabled}
        or observed["enabled"] is not enabled
    ):
        raise ValueError("Canonical s3r.ch TEST host owner observation required")


def ensure_organization(db, *, enabled):
    args = {"tenant": TENANT, "org": ORG}
    existing = db.execute(text("""
        SELECT id FROM organizations WHERE id=:org AND tenant_id=:tenant FOR SHARE
    """), args).scalar_one_or_none()
    if existing is None and enabled:
        db.execute(text("""
            INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:org,:tenant,:name)
        """), args | {"name": ORG_NAME})


def provision(engine, activation, observed, *, enabled=True):
    validate(activation, observed, enabled=enabled)
    profile = identifier(GENERATION, "member", TENANT, SUBJECT)
    group = identifier(GENERATION, "group", TENANT, "host")
    args = {"tenant": TENANT, "org": ORG, "network": NETWORK, "subject": SUBJECT, "account": ACCOUNT,
            "profile": profile, "group": group,
            "membership": identifier(GENERATION, "group-member", TENANT, profile, "host")}
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
        """), args).scalar_one()
        db.execute(text("SELECT id FROM groups WHERE id=:group AND tenant_id=:tenant AND name='host' FOR SHARE"),
                   args).scalar_one()
        if db.scalar(text("SELECT EXISTS(SELECT 1 FROM authority_network_admins WHERE user_id=:subject)"), args):
            raise ValueError("Conflicting TEST network authority")
        ensure_organization(db, enabled=enabled)
        person = install_person(db, None, SUBJECT, SUBJECT, EMAIL, fixture_name="Forum Host", create=enabled)
        member = install_person(db, TENANT, profile, SUBJECT, EMAIL, fixture_name="Forum Host", create=enabled)
        if not enabled and person is None and member is None:
            return result("disabled", profile)
        if (person, member) != (SUBJECT, profile):
            raise ValueError("Unexpected existing TEST owner profile")
        scope(db, network=NETWORK)
        declared = db.execute(text("""
            SELECT user_id,account_key,tenant_context FROM authority_fixture_accounts
             WHERE user_id=:subject OR account_key=:account FOR UPDATE
        """), args).one_or_none()
        if declared is None and enabled:
            db.execute(text("""
                INSERT INTO authority_fixture_accounts(user_id,account_key,network_id,tenant_context)
                VALUES(:subject,:account,:network,:tenant)
            """), args)
        elif declared is None or tuple(declared) != (SUBJECT, ACCOUNT, TENANT):
            raise ValueError("Existing TEST subject declaration differs")
        scope(db, TENANT)
        if enabled and db.scalar(text("""
            SELECT EXISTS(SELECT 1 FROM operator_bans WHERE tenant_id=:tenant AND subject_kind='user'
                          AND subject_id IN (:subject,:profile) AND lifted_at IS NULL)
        """), args):
            raise ValueError("TEST owner is banned")
        memberships = db.execute(text("""
            SELECT organization_id,role,can_purchase_leases,enabled
              FROM organization_memberships WHERE tenant_id=:tenant AND user_id=:profile FOR UPDATE
        """), args).all()
        groups = db.execute(text("""
            SELECT id,group_id FROM user_group_memberships WHERE tenant_id=:tenant AND user_id=:profile FOR UPDATE
        """), args).all()
        reserved = db.execute(text("""
            SELECT organization_id FROM authority_host_owners WHERE tenant_id=:tenant AND user_id=:profile FOR UPDATE
        """), args).scalar_one_or_none()
        if reserved is not None:
            if (reserved != ORG or len(memberships) != 1 or tuple(memberships[0])[:3] != (ORG, "member", False)
                    or groups not in ([], [(args["membership"], group)])):
                raise ValueError("Existing TEST Host owner grants differ")
            db.execute(text("""
                UPDATE organization_memberships SET enabled=:enabled
                WHERE tenant_id=:tenant AND organization_id=:org AND user_id=:profile
                  AND enabled IS DISTINCT FROM :enabled
            """), args | {"enabled": enabled})
            if enabled and not groups:
                db.execute(text("""
                    INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id)
                    VALUES(:membership,:tenant,:profile,:group)
                """), args)
            if not enabled and groups:
                db.execute(text("""
                    DELETE FROM user_group_memberships WHERE id=:membership AND tenant_id=:tenant
                      AND user_id=:profile AND group_id=:group
                """), args)
        else:
            if memberships or groups:
                raise ValueError("Existing TEST profile already has separate grants")
            if not enabled:
                return result("disabled", profile)
            db.execute(text("""
                INSERT INTO organization_memberships(tenant_id,organization_id,user_id,role,can_purchase_leases,enabled)
                VALUES(:tenant,:org,:profile,'member',false,true)
            """), args)
            db.execute(text("""
                INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id)
                VALUES(:membership,:tenant,:profile,:group)
            """), args)
            db.execute(text("""
                INSERT INTO authority_host_owners(tenant_id,organization_id,user_id)
                VALUES(:tenant,:org,:profile)
            """), args)
    return result(("existing" if reserved else "provisioned") if enabled else "disabled", profile)


def result(state, profile):
    return {"state": state, "tenant": str(TENANT),
            "organization": str(ORG), "user_id": str(profile), "subject": str(SUBJECT)}


if __name__ == "__main__":
    try:
        payload = json.loads(sys.stdin.buffer.read(4097))
        if (set(payload) != {"activation", "observation", "enabled"} or type(payload["enabled"]) is not bool
                or os.environ.get("USER_TEST_FORUM_HOST_OWNER_ENABLED") != "1"):
            raise ValueError("Explicit TEST owner inputs required")
        engine = create_engine(os.environ["USER_FIXTURE_DATABASE_URL"])
        try:
            print(json.dumps(provision(engine, payload["activation"], payload["observation"], enabled=payload["enabled"])))
        finally:
            engine.dispose()
    except Exception:
        raise SystemExit("User-owned TEST forum Host owner provisioning refused") from None
