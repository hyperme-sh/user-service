"""Narrow service-key purposes for a currently authorized network owner."""

_STORAGE_FAMILIES = tuple(
    frozenset(f"storage:{family}:{operation}" for operation in ("read", "write", "delete"))
    for family in ("objects", "records")
)


# These are separate consumer profiles, not interchangeable permission families.
_REPLAY_PROFILE = frozenset({'storage:replays:consume'})
_MEDIA_PROFILE = frozenset({'storage:objects:read', 'storage:objects:write',
                            'storage:media:read', 'storage:media:write'})
_TEST_VAULT_PROFILE = frozenset({'storage:vault:read', 'storage:vault:write'})
_TEST_FORUM_STATEMENT_PROFILE = frozenset({'acl:statements:read', 'acl:statements:write'})
_TEST_ALLOCATED_PAYLOAD = frozenset({'storage:media:payload:read', 'storage:media:payload:write'})

_PORTAL_TEST_MEDIA_PROFILES = (
    frozenset({'storage:allocations:issue'}),
    frozenset({'storage:media:retire'}),
    frozenset({'storage:media:payload:read'}),
    frozenset({'storage:media:payload:write'}),
    _TEST_ALLOCATED_PAYLOAD,
)


def network_service_key_allowed(
    network: str, purpose: str | None, scopes: list[str], *, canonical_s3rch_test: bool = False,
    canonical_portal_test: bool = False,
) -> bool:
    """Call only after current tenant/network/admin and generation checks.

    Storage keys can carry a least-privilege subset. They cannot combine storage
    families with each other, attestation or unknown permissions. Replay and
    media consumers use their exact declared profiles. Allocation issuance,
    retirement, observation, allocated payload, ACL media, forum statements, and vault records
    and snapshots have explicit TEST profiles. Portal TEST uses only its
    allocation, retirement and payload profiles. None grants organization authority.
    """
    if purpose != "service" or not scopes:
        return False
    if network == "hyperme.sh":
        profile = frozenset(scopes)
        return (canonical_portal_test and len(scopes) == len(profile)
                and profile in _PORTAL_TEST_MEDIA_PROFILES)
    if network != "s3r.ch":
        return False
    if scopes == ["oracles:attest"]:
        return True
    if (scopes in (['storage:media:observe'], ['storage:allocations:issue'], ['storage:media:retire'],
                   ['acl:vault:statements:read'])
            or (len(scopes) == 2 and frozenset(scopes) in (_TEST_ALLOCATED_PAYLOAD, _TEST_VAULT_PROFILE, _TEST_FORUM_STATEMENT_PROFILE))
            or (len(scopes) == 2 and set(scopes) == {'acl:media:read', 'acl:media:write'})):
        return canonical_s3rch_test
    if len(scopes) == len(set(scopes)) and frozenset(scopes) in (_REPLAY_PROFILE, _MEDIA_PROFILE):
        return True
    return (len(scopes) <= 3 and len(scopes) == len(set(scopes))
            and any(set(scopes) <= family for family in _STORAGE_FAMILIES))
