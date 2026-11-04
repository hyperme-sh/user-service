"""Runtime imports and dependency provenance belong to installed distributions."""
from importlib.metadata import distribution
from importlib.util import find_spec
import json
import re



def test_runtime_layout_and_exact_private_dependencies():
    package = distribution('user-service')
    assert find_spec('user_service.app').origin.endswith('/user_service/app.py')
    # Each direct private dependency is immutable and agrees with the package
    # actually installed, including dependencies selected transitively by core.
    pins = {}
    for requirement in package.requires:
        match = re.match(r'([\w-]+) @ git\+https://github.com/hyperme-sh/[^@]+@([0-9a-f]{40})(?:#.*)?$', requirement)
        if match:
            name, revision = match.groups()
            direct = json.loads(distribution(name).read_text('direct_url.json'))
            assert direct['vcs_info']['commit_id'] == revision
            pins[name] = revision
    assert {'auth-service', 'controlplane-core', 'controlplane-db', 'controlplane-identity', 'controlplane-tenancy'} <= pins.keys()


def test_flags_are_opt_in_by_default(monkeypatch):
    from controlplane_identity.account_lifecycle import enforcement_enabled
    monkeypatch.delenv('ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED', raising=False)
    assert enforcement_enabled() is False
