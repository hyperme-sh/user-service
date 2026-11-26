"""Offline contracts for the exact desktop renter transition plan."""
import copy
import hashlib
import json
from pathlib import Path
import uuid

import pytest
from sqlalchemy import event, text

from user_service import fixture_topology, visor_desktop_fixture as owner

from user_service.visor_desktop_fixture import GENERATION, ISSUER, RENTER, plan


def inputs(member=RENTER):
    before = json.loads((Path(__file__).parent / "data/canonical-test-fixtures.json").read_bytes())
    old_raw = json.dumps(before).encode()
    subjects = {
        "issuer": ISSUER,
        "generation": GENERATION,
        "manifest_sha256": hashlib.sha256(old_raw).hexdigest(),
        "subjects": [{"account_key": a["key"], **{key: a[key] for key in ("id", "email", "enabled")}}
                     for a in before["accounts"]],
    }
    after = copy.deepcopy(before)
    after["accounts"].append(copy.deepcopy(member))
    return old_raw, subjects, after


def plan_inputs(old_raw, subjects, after, *, override=None, member=RENTER):
    new_raw = json.dumps(after).encode()
    next_bindings = {
        **subjects,
        "manifest_sha256": hashlib.sha256(new_raw).hexdigest(),
        "subjects": [*subjects["subjects"], {"account_key": member["key"],
                     "id": member["id"], "email": member["email"], "enabled": True}],
    }
    if override is not None:
        next_bindings["subjects"][-1]["id"] = override
    return old_raw, new_raw, json.dumps(subjects).encode(), json.dumps(next_bindings).encode()


def compile_plan(*args, **kwargs):
    return plan(*plan_inputs(*args, **kwargs))


def test_exact_desktop_renter_addition():
    result = compile_plan(*inputs())
    assert str(result["subject"]) == RENTER["id"]
    assert result["profile"] != result["subject"]


def test_rejects_foreign_provider_binding_and_existing_fixture_changes():
    old_raw, subjects, after = inputs()
    with pytest.raises(ValueError):
        compile_plan(old_raw, subjects, after, override=after["accounts"][0]["id"])
    after["accounts"][0]["email"] = "changed@test.hyperme.sh"
    with pytest.raises(ValueError):
        compile_plan(old_raw, subjects, after)


@pytest.mark.parametrize("member", [RENTER, owner.PORTAL_MEMBER])
def test_additive_owner_transaction_and_retry(empty_authority_owner, monkeypatch, member):
    from test_fixture_bootstrap import bootstrap

    engine = empty_authority_owner
    before, after, old_bindings, new_bindings = plan_inputs(*inputs(member), member=member)
    fixture = member["key"]
    bootstrap(engine, data=before, bindings=old_bindings)
    # Disposable PostgreSQL uses a generated database, schema and role.
    monkeypatch.setattr(owner, "require_owner", lambda db: None)
    tenant = str(plan(before, after, old_bindings, new_bindings, fixture=fixture)["tenant"])

    def snapshot():
        with engine.begin() as db:
            users = text("SELECT id, keycloak_sub FROM users WHERE tenant_id IS NULL")
            platform = db.execute(users).all()
            db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),
                       {"tenant": tenant})
            profiles = db.execute(text("""
                SELECT id, keycloak_sub FROM users WHERE tenant_id=CAST(:tenant AS uuid)
            """), {"tenant": tenant}).all()
        return {*platform, *profiles}

    users_before = snapshot()

    def interrupt_before_membership(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO organization_memberships"):
            raise RuntimeError("interrupted before membership was written")

    event.listen(engine, "before_cursor_execute", interrupt_before_membership)
    try:
        with pytest.raises(RuntimeError, match="interrupted before membership"):
            owner.apply(engine, before, after, old_bindings, new_bindings, fixture=fixture)
    finally:
        event.remove(engine, "before_cursor_execute", interrupt_before_membership)
    assert snapshot() == users_before

    applied = owner.apply(engine, before, after, old_bindings, new_bindings, fixture=fixture)
    assert applied["changed"] is True
    assert owner.apply(engine, before, after, old_bindings, new_bindings, fixture=fixture) == {**applied, "changed": False}
    users_after = snapshot()
    assert {row for row in users_after if row.keycloak_sub != member["id"]} == users_before
    assert len(users_after) == len(users_before) + 2


def test_portal_member_refuses_billing_and_mismatched_provider_subject():
    member = owner.PORTAL_MEMBER
    before, subjects, after = inputs(member)
    options = {"fixture": member["key"]}
    with pytest.raises(ValueError):
        plan(*plan_inputs(before, subjects, after, member=member, override=RENTER["id"]), **options)
    after["accounts"][-1]["can_purchase_leases"] = True
    with pytest.raises(ValueError):
        plan(*plan_inputs(before, subjects, after, member=member), **options)


def test_portal_member_preserves_the_original_provider_inventory_across_topology(empty_authority_owner, monkeypatch):
    from test_fixture_bootstrap import bootstrap

    engine = empty_authority_owner
    member = owner.PORTAL_MEMBER
    original, subjects, _ = inputs(member)
    before = json.loads(original)
    s3rch = json.dumps({**before, "tenants": [*before["tenants"], fixture_topology.ADDITION]}).encode()
    topology = json.loads(s3rch)
    active = next(tenant for tenant in topology["tenants"] if tenant["key"] == "active")
    startup = {"key": "startup-nightly", "network": "hyperme.sh", "name": "Startup Nightly TEST",
               "active": True, "id": str(uuid.uuid5(uuid.UUID(active["id"]), "startup-nightly-tenant"))}
    topology["tenants"].append(startup)
    installed = json.dumps(topology).encode()
    after = {**topology, "accounts": [*topology["accounts"], member]}
    arguments = plan_inputs(installed, subjects, after, member=member)
    old_bindings = arguments[2]
    bootstrap(engine, data=original, bindings=old_bindings)
    for prior, successor in ((original, s3rch), (s3rch, installed)):
        fixture_topology.transition(engine, prior, successor, operation_id=str(uuid.uuid4()), source_sha="b" * 40)

    monkeypatch.setattr(owner, "require_owner", lambda db: None)
    with pytest.raises(ValueError, match="Sealed TEST topology predecessors required"):
        owner.apply(engine, *arguments, fixture=member["key"])
    with pytest.raises(ValueError, match="Applied TEST topology journal entry required"):
        owner.apply(engine, *arguments, fixture=member["key"],
                    topology_predecessors=(original, s3rch + b"\n"))
    options = {"fixture": member["key"], "topology_predecessors": (original, s3rch)}
    changed = copy.deepcopy(after)
    changed["accounts"][0]["grants"] = []
    with pytest.raises(ValueError):
        owner.apply(engine, *plan_inputs(installed, subjects, changed, member=member), **options)
    with engine.begin() as db:
        assert db.execute(text("SELECT manifest_sha256, subjects_sha256 FROM authority_fixture_generation")).one() == (
            hashlib.sha256(installed).hexdigest(), hashlib.sha256(old_bindings).hexdigest())
    applied = owner.apply(engine, *arguments, **options)
    assert applied["changed"] is True
    assert applied["subject"] == member["id"]
    assert applied["subjects_sha256"] == hashlib.sha256(arguments[3]).hexdigest()
    assert owner.apply(engine, *arguments, **options) == {**applied, "changed": False}
    with engine.begin() as db:
        fixture_topology.topology(db, topology)
