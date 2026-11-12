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
