"""Narrow service-key purposes for a currently authorized network owner."""

_STORAGE_FAMILIES = tuple(
    frozenset(f"storage:{family}:{operation}" for operation in ("read", "write", "delete"))
    for family in ("objects", "records")
)


def network_service_key_allowed(network: str, purpose: str | None, scopes: list[str]) -> bool:
    """Call only after current tenant/network/admin and generation checks.

    Storage keys can carry a least-privilege subset. They cannot combine storage
    families with each other, attestation or unknown permissions, and have no
    organization authority.
    """
    if network != "s3r.ch" or purpose != "service" or not scopes:
        return False
    if scopes == ["oracles:attest"]:
        return True
    return (len(scopes) <= 3 and len(scopes) == len(set(scopes))
            and any(set(scopes) <= family for family in _STORAGE_FAMILIES))
