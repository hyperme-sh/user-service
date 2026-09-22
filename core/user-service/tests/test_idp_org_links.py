from auth_service.claims import ENTRA_GLOBAL_ADMIN_WID, MSA_TENANT_ID, idp_facts_from_claims
from user_service.idp_links import proof_failure

TENANT = "11111111-2222-4333-8444-555555555555"


def test_personal_microsoft_account_is_not_an_organization():
    facts = idp_facts_from_claims(
        {"identity_provider": "microsoft", "tid": MSA_TENANT_ID, "wids": [ENTRA_GLOBAL_ADMIN_WID]}
    )
    assert facts["idp_account"] == "individual"
    assert facts["idp_org"] is None


def test_entra_global_admin_can_link_that_tenant_only():
    facts = idp_facts_from_claims(
        {
            "identity_provider": "microsoft",
            "tid": TENANT,
            "wids": [ENTRA_GLOBAL_ADMIN_WID],
        }
    )
    assert facts["idp_account"] == "organization"
    assert (
        proof_failure(
            provider="microsoft",
            external_key=TENANT.upper(),
            idp_provider=facts["idp_provider"],
            idp_org=facts["idp_org"],
            idp_orgs=facts["idp_orgs"],
            idp_wids=facts["idp_wids"],
        )
        is None
    )
    assert proof_failure(
        provider="microsoft",
        external_key="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        idp_provider=facts["idp_provider"],
        idp_org=facts["idp_org"],
        idp_orgs=facts["idp_orgs"],
        idp_wids=facts["idp_wids"],
    )


def test_member_without_directory_role_cannot_claim_the_tenant():
    reason = proof_failure(
        provider="microsoft",
        external_key=TENANT,
        idp_provider="microsoft",
        idp_org=TENANT,
        idp_orgs=[],
        idp_wids=[],
    )
    assert reason == "This sign-in is not a Global Administrator of that tenant."


def test_google_hosted_domain_must_match():
    facts = idp_facts_from_claims({"identity_provider": "google", "hd": "Acme.com"})
    assert facts["idp_org"] == "Acme.com"
    assert (
        proof_failure(
            provider="google",
            external_key="acme.com",
            idp_provider="google",
            idp_org=facts["idp_org"],
            idp_orgs=[],
            idp_wids=[],
        )
        is None
    )
    assert proof_failure(
        provider="google",
        external_key="other.com",
        idp_provider="google",
        idp_org=facts["idp_org"],
        idp_orgs=[],
        idp_wids=[],
    )


def test_gmail_without_a_hosted_domain_cannot_link():
    facts = idp_facts_from_claims({"identity_provider": "google"})
    assert facts["idp_account"] == "individual"
    assert proof_failure(
        provider="google",
        external_key="gmail.com",
        idp_provider="google",
        idp_org=facts["idp_org"],
        idp_orgs=[],
        idp_wids=[],
    )


def test_broker_attributes_prove_the_same_entra_tenant() -> None:
    """The live token carries idp_provider, idp_org, and idp_wids, not raw tid."""
    facts = idp_facts_from_claims(
        {
            "idp_provider": "microsoft",
            "idp_org": TENANT,
            "idp_wids": [ENTRA_GLOBAL_ADMIN_WID],
        }
    )
    assert facts["idp_account"] == "organization"
    assert (
        proof_failure(
            provider="microsoft",
            external_key=TENANT,
            idp_provider=facts["idp_provider"],
            idp_org=facts["idp_org"],
            idp_orgs=facts["idp_orgs"],
            idp_wids=facts["idp_wids"],
        )
        is None
    )


def test_github_org_on_the_token_can_link_and_another_org_cannot():
    facts = idp_facts_from_claims({"identity_provider": "github", "orgs": ["FyberLabs"]})
    assert (
        proof_failure(
            provider="github",
            external_key="fyberlabs",
            idp_provider="github",
            idp_org=facts["idp_org"],
            idp_orgs=facts["idp_orgs"],
            idp_wids=[],
        )
        is None
    )
    assert proof_failure(
        provider="github",
        external_key="someone-else",
        idp_provider="github",
        idp_org=facts["idp_org"],
        idp_orgs=facts["idp_orgs"],
        idp_wids=[],
    )
