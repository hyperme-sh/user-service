from unittest.mock import Mock

import pytest

from user_service.s3rch_forum_host_fixture import (
    EMAIL, ISSUER, ORG, ORG_NAME, SUBJECT, TENANT, ensure_organization, validate,
)


ACTIVATION = {"manifest_sha256": "a" * 64, "subjects_sha256": "b" * 64,
              "tenant": str(TENANT), "organization": str(ORG)}
OBSERVATION = {"issuer": ISSUER, "subject": str(SUBJECT), "email": EMAIL,
               "tenant": str(TENANT), "enabled": True}


def test_accepts_the_declared_test_idp_subject():
    validate(ACTIVATION, OBSERVATION)


@pytest.mark.parametrize("change", [
    {"issuer": "https://auth.hyperme.sh/realms/controlplane"},
    {"email": "s3r-network-admin@test.s3r.ch"},
    {"subject": str(ORG)},
    {"tenant": str(ORG)},
    {"enabled": False},
    {"enabled": 1},
])
def test_refuses_foreign_or_disabled_subject(change):
    with pytest.raises(ValueError):
        validate(ACTIVATION, OBSERVATION | change)


def test_refuses_other_org_or_unsealed_configuration():
    for change in ({"organization": str(TENANT)}, {"manifest_sha256": "missing"}):
        with pytest.raises(ValueError):
            validate(ACTIVATION | change, OBSERVATION)


def test_disabling_requires_the_same_actually_disabled_provider_identity():
    validate(ACTIVATION, OBSERVATION | {"enabled": False}, enabled=False)
    with pytest.raises(ValueError):
        validate(ACTIVATION, OBSERVATION, enabled=False)


@pytest.mark.parametrize("existing,enabled,creates", [
    (None, True, True), (ORG, True, False), (None, False, False), (ORG, False, False),
])
def test_primary_organization_is_added_only_when_enabling_a_missing_fixture(existing, enabled, creates):
    db = Mock()
    db.execute.return_value.scalar_one_or_none.return_value = existing
    ensure_organization(db, enabled=enabled)
    assert db.execute.call_count == 1 + creates
    if creates:
        query, values = db.execute.call_args.args
        assert "INSERT INTO organizations" in str(query)
        assert values == {"tenant": TENANT, "org": ORG, "name": ORG_NAME}
