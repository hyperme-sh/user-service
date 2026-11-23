from contextlib import nullcontext
from unittest.mock import Mock

import pytest

from user_service import s3rch_forum_renter_fixture as fixture

ACTIVATION = {"manifest_sha256": "a" * 64, "subjects_sha256": "b" * 64,
              "tenant": str(fixture.TENANT), "organization": str(fixture.ORG)}
OBSERVATION = {"issuer": fixture.ISSUER, "subject": str(fixture.SUBJECT), "email": fixture.EMAIL,
               "tenant": str(fixture.TENANT), "enabled": True}


@pytest.mark.parametrize("change", [
    {"tenant": str(fixture.ORG)}, {"enabled": False}, {"enabled": 1},
    {"issuer": "https://auth.hyperme.sh/realms/controlplane"},
    {"email": "s3r-network-admin@test.s3r.ch"}, {"subject": str(fixture.ORG)},
])
def test_requires_the_exact_enabled_test_issuer_observation(change):
    with pytest.raises(ValueError):
        fixture.validate(ACTIVATION, OBSERVATION | change)


def test_refuses_a_changed_canonical_organization():
    with pytest.raises(ValueError):
        fixture.validate(ACTIVATION | {"organization": str(fixture.TENANT)}, OBSERVATION)


def owner_db(monkeypatch, *, existing=False, group_name="renter", sealed=True, granted=True, profile_exists=True):
    db = Mock()
    engine = Mock(begin=Mock(return_value=nullcontext(db)))
    profile = fixture.identifier(fixture.GENERATION, "member", fixture.TENANT, fixture.SUBJECT)
    group = fixture.identifier(fixture.GENERATION, "group", fixture.TENANT, group_name)
    membership = fixture.identifier(fixture.GENERATION, "group-member", fixture.TENANT, profile, "renter")
    writes = []

    def execute(query, params=None):
        statement = str(query)
        result = Mock()
        if statement.lstrip().startswith(("INSERT INTO", "UPDATE", "DELETE FROM")):
            writes.append(statement)
        elif "FROM authority_fixture_generation" in statement:
            result.one.return_value = (fixture.GENERATION, ("a" if sealed else "z") * 64, "b" * 64)
        elif "FROM authority_fixture_accounts" in statement:
            declared = (fixture.SUBJECT, fixture.ACCOUNT, fixture.TENANT)
            result.one_or_none.return_value = declared if existing else None
        elif "FROM organization_memberships" in statement:
            result.all.return_value = [(fixture.ORG, "member", True, granted)] if existing else []
        elif "FROM user_group_memberships" in statement:
            result.all.return_value = [(membership, group)] if existing and granted else []
        return result

    db.execute.side_effect = execute
    db.scalar.return_value = False
    monkeypatch.setattr(fixture, "require_test_owner", Mock())
    monkeypatch.setattr(fixture, "ensure_organization", Mock())
    monkeypatch.setattr(fixture, "install_person", Mock(side_effect=[fixture.SUBJECT, profile]
                                                       if profile_exists else [None, None]))
    return engine, writes


@pytest.mark.parametrize("existing", [False, True])
def test_grants_only_ordinary_renter_authority_and_retries_without_writes(monkeypatch, existing):
    engine, writes = owner_db(monkeypatch, existing=existing)
    result = fixture.provision(engine, ACTIVATION, OBSERVATION)
    assert result["user_id"] == result["subject"] == str(fixture.SUBJECT)
    assert result["state"] == ("existing" if existing else "provisioned")
    if existing:
        assert writes == []
    else:
        assert [sql.split("INSERT INTO ")[1].split("(")[0] for sql in writes] == [
            "organization_memberships", "user_group_memberships", "authority_fixture_accounts",
        ]
        assert "'member',true,true" in writes[0]


@pytest.mark.parametrize("binding", [{"sealed": False}, {"existing": True, "group_name": "host"}])
def test_refuses_changed_generation_or_unexpected_existing_grants(monkeypatch, binding):
    engine, writes = owner_db(monkeypatch, **binding)
    with pytest.raises(ValueError):
        fixture.provision(engine, ACTIVATION, OBSERVATION)
    assert writes == []


@pytest.mark.parametrize("existing,granted", [(False, False), (True, True), (True, False)])
def test_teardown_disables_only_owned_grants_and_handles_partial_setup(monkeypatch, existing, granted):
    engine, writes = owner_db(monkeypatch, existing=existing, granted=granted, profile_exists=existing)
    result = fixture.provision(engine, ACTIVATION, OBSERVATION | {"enabled": False}, enabled=False)
    assert result["state"] == "disabled"
    assert len(writes) == (2 if granted else 0)
    if writes:
        assert "UPDATE organization_memberships SET enabled=:enabled" in writes[0]
        assert "DELETE FROM user_group_memberships" in writes[1]
    assert [call.kwargs["create"] for call in fixture.install_person.call_args_list] == [False, False]
