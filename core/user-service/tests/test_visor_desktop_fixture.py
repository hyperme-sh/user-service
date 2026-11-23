"""Offline contracts for the exact desktop renter transition plan."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import text

from user_service import visor_desktop_fixture as owner

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
