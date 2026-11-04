"""Distinguish native global authority from transported tenant/key permissions."""

import pytest
from controlplane_api.config import settings
from fastapi import HTTPException
from user_service.closure_authorization import account_subject, global_closure_operator


@pytest.fixture
def native(monkeypatch):
    monkeypatch.setattr(
        settings, "keycloak_issuer", "https://id.example/realms/accounts"
    )
    return {
        "sub": "exact-opaque-subject",
        "iss": settings.keycloak_issuer,
        "realm_access": {"roles": ["account:close"]},
    }


@pytest.mark.parametrize("subject", ["human-subject", "ai-service-account-subject"])
def test_explicit_native_realm_role_can_authorize_human_or_ai(native, subject):
    native["sub"] = subject
    assert global_closure_operator(native) == subject


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://other.example/realms/accounts"},
        {"iss": None},
        {"realm_access": {"roles": "account:close"}},
        {"realm_access": {"roles": ["account:close", None]}},
        {"realm_access": {"roles": ["tenant-support"]}},
        {"realm_access": None, "permissions": ["account:close"]},
        {"realm_access": None, "groups": ["account:close"]},
        {"spanopticon_auth": "tenant_session"},
        {"spanopticon_auth": "api_key"},
        {"api_key_id": "credential"},
        {"key_id": None},
        {"purpose": "host_setup"},
        {"sub": "apikey:credential"},
    ],
)
def test_untrusted_or_transported_roles_never_authorize_global_action(native, change):
    native.update(change)
    with pytest.raises(HTTPException) as error:
        global_closure_operator(native)
    assert error.value.status_code == 403


def test_tenant_session_can_only_identify_its_own_exact_account(native):
    native["spanopticon_auth"] = "tenant_session"
    assert account_subject(native) == "exact-opaque-subject"
    with pytest.raises(HTTPException):
        global_closure_operator(native)
