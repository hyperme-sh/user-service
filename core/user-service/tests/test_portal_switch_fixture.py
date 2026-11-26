from contextlib import nullcontext
from unittest.mock import Mock

import pytest

from user_service import portal_switch_fixture as fixture

ACTIVATION = {
    "manifest_sha256": "a" * 64,
    "subjects_sha256": "b" * 64,
    "organizations": {str(tenant): str(org) for _, tenant, org in fixture.DESTINATIONS},
}
OBSERVATION = {
    "issuer": fixture.ISSUER,
    "email": fixture.EMAIL,
    "subject": str(fixture.SUBJECT),
    "enabled": True,
}


@pytest.mark.parametrize("field,value", [
    ("issuer", "https://auth.hyperme.sh/realms/controlplane"),
    ("email", "admin@test.hyperme.sh"),
    ("subject", "00000000-0000-0000-0000-000000000000"),
    ("enabled", 1),
])
def test_requires_the_declared_test_identity(field, value):
    with pytest.raises(ValueError, match="dedicated Portal TEST identity"):
        fixture.validate(ACTIVATION, OBSERVATION | {field: value})


def test_refuses_membership_outside_the_declared_organizations():
    with pytest.raises(ValueError, match="declared TEST Portal organizations"):
        fixture.validate(ACTIVATION | {"organizations": {}}, OBSERVATION)


@pytest.mark.parametrize("existing", [False, True])
def test_provisions_only_ordinary_memberships_and_can_retry(monkeypatch, existing):
    db = Mock()
    engine = Mock(begin=Mock(return_value=nullcontext(db)))
    profiles = [fixture.identifier(fixture.GENERATION, "member", tenant, fixture.SUBJECT)
                for _, tenant, _ in fixture.DESTINATIONS]
    monkeypatch.setattr(fixture, "require_test_owner", Mock())
    monkeypatch.setattr(fixture, "scope", Mock())
    monkeypatch.setattr(fixture, "install_person", Mock(side_effect=[fixture.SUBJECT, *profiles]))
    writes = []

    def execute(query, params=None):
        statement = str(query)
        result = Mock()
        if "FROM authority_fixture_generation" in statement:
            result.one.return_value = (fixture.GENERATION, "a" * 64, "b" * 64)
        if "FROM organization_memberships" in statement:
            result.all.return_value = [(params["organization"], "member", False, True)] if existing else []
        if "INSERT INTO organization_memberships" in statement:
            assert "'member',false,true" in statement
            writes.append((params["tenant"], params["organization"]))
        return result

    db.execute.side_effect = execute
    db.scalar.return_value = False
    assert fixture.provision(engine, ACTIVATION, OBSERVATION) == {
        "subject": str(fixture.SUBJECT), "organizations": ACTIVATION["organizations"]
    }
    expected = [] if existing else [(tenant, org) for _, tenant, org in fixture.DESTINATIONS]
    assert writes == expected


def test_disabling_removes_only_the_declared_ordinary_memberships(monkeypatch):
    db = Mock()
    engine = Mock(begin=Mock(return_value=nullcontext(db)))
    db.execute.return_value.one.return_value = (fixture.GENERATION, "a" * 64, "b" * 64)
    monkeypatch.setattr(fixture, "require_test_owner", Mock())
    monkeypatch.setattr(fixture, "scope", Mock())
    monkeypatch.setattr(fixture, "install_person", Mock())

    fixture.provision(engine, ACTIVATION, OBSERVATION | {"enabled": False})

    fixture.install_person.assert_not_called()
    deletes = [call.args for call in db.execute.call_args_list if "DELETE FROM" in str(call.args[0])]
    assert [(params["tenant"], params["organization"]) for _, params in deletes] == [
        (tenant, org) for _, tenant, org in fixture.DESTINATIONS
    ]
    for query, params in deletes:
        assert "role='member' AND NOT can_purchase_leases" in str(query)
        assert params["member"] == fixture.identifier(fixture.GENERATION, "member", params["tenant"], fixture.SUBJECT)
