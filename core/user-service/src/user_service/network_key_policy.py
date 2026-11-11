"""Narrow service-key purposes for a currently authorized network owner."""

_STORAGE_SCOPES = frozenset({"storage:objects:read", "storage:objects:write", "storage:objects:delete"})


def network_service_key_allowed(network: str, purpose: str | None, scopes: list[str]) -> bool:
    """Call only after current tenant/network/admin and generation checks.

    Storage keys can carry a least-privilege subset. They cannot combine storage
    with attestation or unknown permissions, and have no organization authority.
    """
    if network != "s3r.ch" or purpose != "service" or not scopes:
        return False
    if scopes == ["oracles:attest"]:
        return True
    return len(scopes) <= 3 and len(scopes) == len(set(scopes)) and set(scopes) <= _STORAGE_SCOPES
