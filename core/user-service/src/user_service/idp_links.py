"""Prove the signed-in organization owner controls an identity-provider org.

The link is saved on the Panopticon organization. Key Vault does not hold it.
"""

from __future__ import annotations

from auth_service.claims import ENTRA_GLOBAL_ADMIN_WID, MSA_TENANT_ID

PROVIDERS = ("microsoft", "google", "github")


def normalize_external_key(provider: str, external_key: str) -> str:
    key = external_key.strip()
    if provider == "microsoft":
        return key.lower()
    if provider == "google":
        return key.lower().rstrip(".")
    return key.lower()


def proof_failure(
    *,
    provider: str,
    external_key: str,
    idp_provider: str | None,
    idp_org: str | None,
    idp_orgs: list[str] | None,
    idp_wids: list[str] | None,
) -> str | None:
    """None when this sign-in administers that org. Otherwise a short reason."""
    if provider not in PROVIDERS:
        return "Unknown identity provider."
    key = normalize_external_key(provider, external_key)
    if not key:
        return "Organization key is empty."
    if (idp_provider or "") != provider:
        return "Sign in with that identity provider before linking it."
    orgs = [item.strip() for item in (idp_orgs or []) if item.strip()]
    wids = {item.lower() for item in (idp_wids or [])}
    if provider == "microsoft":
        tid = (idp_org or "").strip().lower()
        if not tid or tid == MSA_TENANT_ID:
            return "A personal Microsoft account cannot link an organization."
        if tid != key:
            return "This sign-in is a different Microsoft organization."
        if ENTRA_GLOBAL_ADMIN_WID not in wids:
            return "This sign-in is not a Global Administrator of that tenant."
        return None
    if provider == "google":
        hosted = (idp_org or "").strip().lower().rstrip(".")
        if not hosted:
            return "This Google account has no hosted domain."
        if hosted != key:
            return "This sign-in is a different Google organization."
        return None
    names = {item.lower() for item in orgs}
    if (idp_org or "").strip():
        names.add(idp_org.strip().lower())
    if key.lower() not in names:
        return "This GitHub sign-in is not a member of that organization."
    return None
