"""Narrow service-key purposes for a currently authorized network owner."""

_STORAGE_FAMILIES = tuple(
    frozenset(f"storage:{family}:{operation}" for operation in ("read", "write", "delete"))
    for family in ("objects", "records")
)


# These are separate consumer profiles, not interchangeable permission families.
_REPLAY_PROFILE = frozenset({'storage:replays:consume'})
_MEDIA_PROFILE = frozenset({'storage:objects:read', 'storage:objects:write',
                            'storage:media:read', 'storage:media:write'})


def network_service_key_allowed(
    network: str, purpose: str | None, scopes: list[str], *, canonical_s3rch_test: bool = False,
) -> bool:
    """Call only after current tenant/network/admin and generation checks.

    Storage keys can carry a least-privilege subset. They cannot combine storage
    families with each other, attestation or unknown permissions. Replay and
    media consumers use their exact declared profiles. Observer keys are limited
    to the canonical s3r.ch TEST tenant. None grants organization authority.
    """
    if network != "s3r.ch" or purpose != "service" or not scopes:
        return False
    if scopes == ["oracles:attest"]:
        return True
    if scopes == ['storage:media:observe']:
        return canonical_s3rch_test
    if len(scopes) == len(set(scopes)) and frozenset(scopes) in (_REPLAY_PROFILE, _MEDIA_PROFILE):
        return True
    return (len(scopes) <= 3 and len(scopes) == len(set(scopes))
            and any(set(scopes) <= family for family in _STORAGE_FAMILIES))
