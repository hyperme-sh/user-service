"""Closure authorization from verified raw claims, before creating any intent."""

from __future__ import annotations

from controlplane_api.config import settings
from fastapi import HTTPException


def account_subject(claims: dict) -> str:
    """Do not turn an exchanged API-key credential into its account owner's grant."""
    subject = claims.get("sub")
    if (
        not isinstance(subject, str)
        or not subject.strip()
        or len(subject) > 512
        or subject.startswith("apikey:")
        or claims.get("spanopticon_auth") == "api_key"
        or "api_key_id" in claims
        or "key_id" in claims
        or claims.get("purpose")
    ):
        raise HTTPException(403, "Account identity required")
    return subject


def global_closure_operator(claims: dict) -> str:
    """Only an explicitly assigned native realm role grants global closure."""
    subject = account_subject(claims)
    realm = claims.get("realm_access")
    roles = realm.get("roles") if isinstance(realm, dict) else None
    issuer = settings.keycloak_issuer
    if (
        not issuer
        or claims.get("iss") != issuer.rstrip("/")
        or claims.get("spanopticon_auth")
        or not isinstance(roles, list)
        or not all(isinstance(role, str) for role in roles)
        or "account:close" not in roles
    ):
        raise HTTPException(403, "Global account closure authority required")
    return subject
