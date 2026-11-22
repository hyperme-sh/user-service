import pytest

from user_service.s3rch_forum_host_fixture import EMAIL, ISSUER, ORG, SUBJECT, TENANT, validate


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
