"""One-time configured TEST identities for a fresh User owner schema."""

import argparse
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import uuid
from sqlalchemy import create_engine, text

NAMESPACE = uuid.UUID("55462e7c-b03c-494c-aaba-e5e0f7b46097")


def identifier(generation, *parts):
    return uuid.uuid5(NAMESPACE, ":".join([generation, *map(str, parts)]))


def validate(manifest, bindings, *, generation, issuer):
    if (
        manifest["schema_version"] != 1
        or manifest["environment"] != "test"
        or manifest["generation"] != generation
    ):
        raise ValueError("Exact declared TEST generation required")
    networks = {row["id"]: row for row in manifest["networks"]}
    tenants = {row["key"]: row for row in manifest["tenants"]}
    orgs = {row["key"]: row for row in manifest["organizations"]}
    accounts = {row["key"]: row for row in manifest["accounts"]}
    for key, name in [
        ("networks", networks),
        ("tenants", tenants),
        ("organizations", orgs),
        ("accounts", accounts),
    ]:
        if len(name) != len(manifest[key]):
            raise ValueError("Duplicate configuration identities")
    if len(tenants) != 2 or sum(row["active"] is True for row in tenants.values()) != 1:
        raise ValueError("TEST requires the active/isolation tenant pair")
    if bindings["issuer"] != issuer or bindings["generation"] != generation:
        raise ValueError("Identity inventory belongs to another authority")
    subjects = {row["account_key"]: row for row in bindings["subjects"]}
    if len(subjects) != len(bindings["subjects"]) or set(subjects) != set(accounts):
        raise ValueError("Identity inventory differs from configured accounts")
    emails = set()
    admin_map = {}
    for key, account in accounts.items():
        uid = uuid.UUID(account["id"])
        row = subjects[key]
        if (
            str(uid) != row["id"]
            or row["email"].lower() != account["email"].lower()
            or row["enabled"] is not account["enabled"]
        ):
            raise ValueError("Provider identity binding differs")
        if account["email"].lower() in emails:
            raise ValueError("Duplicate fixture email")
        emails.add(account["email"].lower())
        context = account["tenant_context"]
        if context is not None and context not in tenants:
            raise ValueError("Unknown tenant context")
        for grant in account["grants"]:
            scope, target, role = grant["scope"], grant["target"], grant["role"]
            if scope == "network":
                if (
                    target not in networks
                    or role != "admin"
                    or context is not None
                    or len(account["grants"]) != 1
                    or target in admin_map
                ):
                    raise ValueError("Network admin cannot imply tenant/org authority")
                admin_map[target] = key
            elif scope == "tenant":
                if target != context or role != "admin":
                    raise ValueError("Tenant grant scope differs")
            elif scope == "organization":
                if (
                    target not in orgs
                    or orgs[target]["tenant"] != context
                    or role not in ("admin", "member")
                ):
                    raise ValueError("Organization grant scope differs")
            else:
                raise ValueError("Unknown authority scope")
        if account["can_purchase_leases"] and (
            not account["enabled"]
            or not any(g["scope"] == "organization" for g in account["grants"])
        ):
            raise ValueError("Billing requires an active org member")
    if admin_map != {key: row["admin"] for key, row in networks.items()}:
        raise ValueError("Configured network admin map differs")
    for tenant in tenants.values():
        uuid.UUID(tenant["id"])
        if tenant["network"] not in networks:
            raise ValueError("Unknown tenant network")
    for org in orgs.values():
        uuid.UUID(org["id"])
        if org["tenant"] not in tenants:
            raise ValueError("Unknown organization tenant")
    host_orgs = {}
    for host in manifest["hosts"]:
        owner = accounts.get(host["owner"])
        organization = orgs.get(host["organization"])
        if (
            not owner
            or not owner["host_owner"]
            or not owner["enabled"]
            or not organization
            or owner["tenant_context"] != organization["tenant"]
            or host["sell_state"] != "paused"
            or host["require_fresh_enrollment"] is not True
            or host["copy_prior_certification"] is not False
            or not any(
                g["scope"] == "organization" and g["target"] == host["organization"]
                for g in owner["grants"]
            )
        ):
            raise ValueError(
                "Host must have a configured active owner organization and fresh paused enrollment"
            )
        if (
            host["owner"] in host_orgs
            and host_orgs[host["owner"]] != host["organization"]
        ):
            raise ValueError("One host owner context must resolve to one organization")
        host_orgs[host["owner"]] = host["organization"]
    if set(host_orgs) != {key for key, a in accounts.items() if a["host_owner"]}:
        raise ValueError("Host ownership capability must match configured hosts")
    return networks, tenants, orgs, accounts, subjects


def seed(
    engine,
    manifest_bytes,
    bindings_bytes,
    *,
    generation,
    issuer,
    manifest_sha256,
    source_sha
):
    if (
        hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256
        or re.fullmatch("[a-f0-9]{40}", source_sha) is None
    ):
        raise ValueError("Exact configuration and source identities required")
    manifest = json.loads(manifest_bytes)
    bindings = json.loads(bindings_bytes)
    networks, tenants, orgs, accounts, subjects = validate(
        manifest, bindings, generation=generation, issuer=issuer
    )
    schema_sha = hashlib.sha256(
        files("user_service").joinpath("authority_schema.sql").read_bytes()
    ).hexdigest()
    with engine.begin() as db:
        flags = (
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
                flags[key]
                for key in [
                    "rolsuper",
                    "rolbypassrls",
                    "rolcreaterole",
                    "rolcreatedb",
                    "rolreplication",
                ]
            )
            or not flags["owns_schema"]
            or flags["nspname"] == "public"
        ):
            raise ValueError("Bootstrap requires the nonprivileged User schema owner")
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))")
        )
        if db.execute(
            text("SELECT revision,sha256 FROM owner_authority_version")
        ).all() != [("0002_authority", schema_sha)]:
            raise ValueError("Scoped authority migration identity differs")
        db.execute(
            text(
                "SELECT set_config('app.current_tenant_id','',true),set_config('app.current_network_id','',true)"
            )
        )
        if (
            db.scalar(text("SELECT count(*) FROM authority_fixture_generation"))
            or db.scalar(text("SELECT count(*) FROM tenants"))
            or db.scalar(text("SELECT count(*) FROM users"))
        ):
            raise ValueError(
                "Fixture bootstrap requires a fresh empty owner; it never repairs live roles"
            )

        def scope(tenant=None, network=None):
            db.execute(
                text(
                    "SELECT set_config('app.current_tenant_id',:tenant,true),set_config('app.current_network_id',:network,true)"
                ),
                {"tenant": str(tenant) if tenant else "", "network": network or ""},
            )

        for network in networks:
            scope(network=network)
            db.execute(
                text("INSERT INTO authority_networks(id) VALUES(:id)"), {"id": network}
            )
        roles = {}
        profiles = {}
        for key, tenant in tenants.items():
            tid = uuid.UUID(tenant["id"])
            scope(tid)
            db.execute(
                text(
                    "INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,:active)"
                ),
                {"id": tid, "name": tenant["name"], "active": tenant["active"]},
            )
            db.execute(
                text("INSERT INTO authority_tenants VALUES(:id,:network)"),
                {"id": tid, "network": tenant["network"]},
            )
            for name in ["user", "admin", "host"]:
                rid = identifier(generation, "role", tid, name)
                roles[key, name] = rid
                db.execute(
                    text(
                        "INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,:name,'[]'::jsonb)"
                    ),
                    {"id": rid, "tenant": tid, "name": name},
                )
            for group in ["renter", "host"]:
                gid = identifier(generation, "group", tid, group)
                db.execute(
                    text(
                        "INSERT INTO groups(id,tenant_id,name,role_id) VALUES(:id,:tenant,:name,:role)"
                    ),
                    {
                        "id": gid,
                        "tenant": tid,
                        "name": group,
                        "role": roles[key, "host" if group == "host" else "user"],
                    },
                )
        for key, org in orgs.items():
            tid = uuid.UUID(tenants[org["tenant"]]["id"])
            scope(tid)
            db.execute(
                text(
                    "INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:id,:tenant,:name)"
                ),
                {
                    "id": uuid.UUID(org["id"]),
                    "tenant": tid,
                    "name": org.get("legal_name", key + " TEST organization"),
                },
            )
        for key, account in accounts.items():
            uid = uuid.UUID(account["id"])
            subject = subjects[key]["id"]
            context = account["tenant_context"]
            network = next(
                (g["target"] for g in account["grants"] if g["scope"] == "network"),
                None,
            )
            network = network or tenants[context]["network"]
            scope(network=network)
            db.execute(
                text(
                    "INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,NULL,:sub,:email,:first,'Fixture','unspecified',:active)"
                ),
                {
                    "id": uid,
                    "sub": subject,
                    "email": account["email"],
                    "first": key,
                    "active": account["enabled"],
                },
            )
            db.execute(
                text(
                    "INSERT INTO authority_fixture_accounts VALUES(:id,:key,:network,:context)"
                ),
                {
                    "id": uid,
                    "key": key,
                    "network": network,
                    "context": uuid.UUID(tenants[context]["id"]) if context else None,
                },
            )
            for grant in account["grants"]:
                if grant["scope"] == "network":
                    db.execute(
                        text(
                            "INSERT INTO authority_network_admins(network_id,user_id) VALUES(:network,:user)"
                        ),
                        {"network": network, "user": uid},
                    )
            if context is None:
                continue
            tid = uuid.UUID(tenants[context]["id"])
            scope(tid)
            pid = identifier(generation, "member", tid, uid)
            profiles[key] = pid
            role = (
                "admin"
                if any(
                    g["scope"] == "tenant" and g["role"] == "admin"
                    for g in account["grants"]
                )
                else "user"
            )
            db.execute(
                text(
                    "INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id) VALUES(:id,:tenant,:sub,:email,:first,'Fixture','unspecified',:active,:role)"
                ),
                {
                    "id": pid,
                    "tenant": tid,
                    "sub": subject,
                    "email": account["email"],
                    "first": key,
                    "active": account["enabled"],
                    "role": roles[context, role],
                },
            )
            for grant in account["grants"]:
                if grant["scope"] == "organization":
                    db.execute(
                        text(
                            "INSERT INTO organization_memberships VALUES(:tenant,:org,:user,:role,:pays,true)"
                        ),
                        {
                            "tenant": tid,
                            "org": uuid.UUID(orgs[grant["target"]]["id"]),
                            "user": pid,
                            "role": grant["role"],
                            "pays": account["can_purchase_leases"],
                        },
                    )
            for group, include in [
                ("host", account["host_owner"]),
                ("renter", account["can_purchase_leases"]),
            ]:
                if include:
                    db.execute(
                        text(
                            "INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id) VALUES(:id,:tenant,:user,:group)"
                        ),
                        {
                            "id": identifier(
                                generation, "group-member", tid, pid, group
                            ),
                            "tenant": tid,
                            "user": pid,
                            "group": identifier(generation, "group", tid, group),
                        },
                    )
        for key in {h["owner"] for h in manifest["hosts"]}:
            host = next(h for h in manifest["hosts"] if h["owner"] == key)
            tid = uuid.UUID(tenants[accounts[key]["tenant_context"]]["id"])
            scope(tid)
            db.execute(
                text("INSERT INTO authority_host_owners VALUES(:tenant,:org,:user)"),
                {
                    "tenant": tid,
                    "org": uuid.UUID(orgs[host["organization"]]["id"]),
                    "user": profiles[key],
                },
            )
        db.execute(
            text(
                "INSERT INTO authority_fixture_generation(generation,manifest_sha256,subjects_sha256,source_sha) VALUES(:generation,:manifest,:subjects,:source)"
            ),
            {
                "generation": generation,
                "manifest": manifest_sha256,
                "subjects": hashlib.sha256(bindings_bytes).hexdigest(),
                "source": source_sha,
            },
        )
    return {
        "generation": generation,
        "manifest_sha256": manifest_sha256,
        "subjects_sha256": hashlib.sha256(bindings_bytes).hexdigest(),
        "source_sha": source_sha,
        "networks": len(networks),
        "tenants": len(tenants),
        "organizations": len(orgs),
        "identities": len(accounts),
        "tenant_profiles": len(profiles),
        "runtime_accepted": False,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ["manifest", "subject-bindings", "database-url-file", "receipt"]:
        p.add_argument("--" + arg, type=Path, required=True)
    for arg in ["generation", "issuer", "manifest-sha256", "source-sha"]:
        p.add_argument("--" + arg, required=True)
    a = p.parse_args()
    engine = create_engine(a.database_url_file.read_text().strip())
    descriptor = os.open(a.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        result = seed(
            engine,
            a.manifest.read_bytes(),
            a.subject_bindings.read_bytes(),
            generation=a.generation,
            issuer=a.issuer,
            manifest_sha256=a.manifest_sha256,
            source_sha=a.source_sha,
        )
        with os.fdopen(descriptor, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        print(
            "Configured User fixture generation seeded; runtime acceptance remains separate"
        )
    finally:
        engine.dispose()
