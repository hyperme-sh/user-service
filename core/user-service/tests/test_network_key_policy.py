"""Pure unit policy tests; no database, identity provider or service calls."""
from itertools import combinations, permutations

import pytest

from user_service.network_key_policy import network_service_key_allowed


@pytest.mark.parametrize("family", ["objects", "records"])
def test_read_only_write_only_delete_only_and_combined_storage_keys(family):
    scopes = tuple(f"storage:{family}:{op}" for op in ("read", "write", "delete"))
    for size in range(1, 4):
        for subset in combinations(scopes, size):
            for ordering in permutations(subset):
                assert network_service_key_allowed('s3r.ch', 'service', list(ordering))
    assert network_service_key_allowed('s3r.ch', 'service', ['oracles:attest'])


@pytest.mark.parametrize('network,purpose,scopes', [
    ('hyperme.sh', 'service', ['storage:objects:read']),
    ('s3r.ch.attacker', 'service', ['storage:objects:read']),
    ('s3r.ch', 'renter', ['storage:objects:read']),
    ('s3r.ch', 'ir', ['storage:objects:read']),
    ('s3r.ch', None, ['storage:objects:read']),
    ('s3r.ch', 'service', []),
    ('s3r.ch', 'service', ['storage:objects:read', 'storage:objects:read']),
    ('s3r.ch', 'service', ['storage:objects:read', 'oracles:attest']),
    ('s3r.ch', 'service', ['storage:objects:read', 'storage:settings:write']),
    ('s3r.ch', 'service', ['storage:*']),
    ('s3r.ch', 'service', ['storage:objects:READ']),
    ('s3r.ch', 'service', ['storage:objects:read ']),
    ('s3r.ch', 'service', ['oracles:attest', 'oracles:attest']),
])
def test_no_cross_network_cross_purpose_duplicate_mixed_or_unknown_permissions(network, purpose, scopes):
    assert not network_service_key_allowed(network, purpose, scopes)


@pytest.mark.parametrize("family", ["objects", "records"])
@pytest.mark.parametrize("network,purpose", [("hyperme.sh", "service"), ("s3r.ch.attacker", "service"), ("s3r.ch", "renter"), ("s3r.ch", "ir"), ("s3r.ch", None)])
def test_storage_families_cannot_cross_authority(network, purpose, family):
    assert not network_service_key_allowed(network, purpose, [f"storage:{family}:read"])


@pytest.mark.parametrize("scopes", [
    ["storage:records:read", "storage:records:read"],
    ["storage:records:read", "oracles:attest"],
    ["storage:records:read", "storage:objects:read"],
    ["storage:objects:write", "storage:records:delete"],
    ["storage:records:read", "storage:settings:write"],
    ["storage:records:*"],
])
def test_records_cannot_mix_permission_families(scopes):
    assert not network_service_key_allowed("s3r.ch", "service", scopes)


PROFILES = [
    ['storage:replays:consume'],
    ['storage:objects:read', 'storage:objects:write', 'storage:media:read', 'storage:media:write'],
]


@pytest.mark.parametrize('profile', PROFILES)
def test_declared_replay_and_media_profiles_are_exact_and_order_independent(profile):
    for ordering in permutations(profile):
        assert network_service_key_allowed('s3r.ch', 'service', list(ordering))
    for extra in ('oracles:attest', 'storage:records:read', 'storage:media:observe', 'storage:objects:delete', profile[0]):
        assert not network_service_key_allowed('s3r.ch', 'service', [*profile, extra])
    for network, purpose in [('hyperme.sh','service'), ('s3r.ch.attacker','service'), ('s3r.ch','renter'), ('s3r.ch','ir')]:
        assert not network_service_key_allowed(network, purpose, profile)


@pytest.mark.parametrize('scopes', [
    ['storage:replays:read'], ['storage:replays:*'], ['storage:media:write'],
    ['storage:objects:read', 'storage:media:write'],
    ['storage:replays:consume', 'storage:objects:read'],
])
def test_profiles_do_not_create_general_media_or_replay_permission_families(scopes):
    assert not network_service_key_allowed('s3r.ch', 'service', scopes)


@pytest.mark.parametrize('scope', ['storage:media:observe', 'storage:allocations:issue', 'storage:media:retire'])
def test_test_media_credentials_require_exact_scope_and_canonical_authority(scope):
    scopes = [scope]
    assert network_service_key_allowed('s3r.ch', 'service', scopes, canonical_s3rch_test=True)
    assert not network_service_key_allowed('s3r.ch', 'service', scopes)
    assert not network_service_key_allowed('s3r.ch', 'renter', scopes, canonical_s3rch_test=True)
    assert not network_service_key_allowed('hyperme.sh', 'service', scopes, canonical_s3rch_test=True)
    for extra in (scope, 'storage:media:write', 'storage:records:read', 'storage:allocations:issue',
                  'storage:media:payload:read'):
        assert not network_service_key_allowed('s3r.ch', 'service', [scope, extra], canonical_s3rch_test=True)
    assert not network_service_key_allowed('s3r.ch', 'service',
        ['storage:media:observe', 'storage:allocations:issue'], canonical_s3rch_test=True)


def test_allocated_payload_requires_the_exact_canonical_test_profile():
    scopes = ['storage:media:payload:read', 'storage:media:payload:write']
    for pair in (scopes, list(reversed(scopes))):
        assert network_service_key_allowed('s3r.ch', 'service', pair, canonical_s3rch_test=True)
        assert not network_service_key_allowed('s3r.ch', 'service', pair)
        assert not network_service_key_allowed('s3r.ch', 'renter', pair, canonical_s3rch_test=True)
        assert not network_service_key_allowed('hyperme.sh', 'service', pair, canonical_s3rch_test=True)
    for mixed in ([scopes[0]], [scopes[1]], [scopes[0], scopes[0]], scopes + ['storage:media:read']):
        assert not network_service_key_allowed('s3r.ch', 'service', mixed, canonical_s3rch_test=True)

def test_acl_media_requires_both_permissions_and_canonical_test():
    media = ['acl:media:read', 'acl:media:write']
    for scopes in (media, list(reversed(media))):
        assert network_service_key_allowed('s3r.ch', 'service', scopes, canonical_s3rch_test=True)
        assert not network_service_key_allowed('s3r.ch', 'service', scopes)
        assert not network_service_key_allowed('s3r.ch', 'renter', scopes, canonical_s3rch_test=True)
        assert not network_service_key_allowed('hyperme.sh', 'service', scopes, canonical_s3rch_test=True)
    for scopes in ([media[0]], [media[1]], [media[0], media[0]], [*media, 'storage:media:observe']):
        assert not network_service_key_allowed('s3r.ch', 'service', scopes, canonical_s3rch_test=True)
