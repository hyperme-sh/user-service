"""Runtime imports and dependency provenance belong to installed distributions."""
from importlib.metadata import distribution
from importlib.util import find_spec
import json
import re
import hashlib
import os
from pathlib import Path
import pytest



def assert_private_provenance(name, revision):
    installed = distribution(name)
    direct = json.loads(installed.read_text('direct_url.json'))
    fixture_manifest = os.environ.get('DEPENDENCY_FIXTURE_MANIFEST')
    if not fixture_manifest:
        assert direct['vcs_info']['commit_id'] == revision
        return
    manifest = Path(fixture_manifest)
    records = json.loads(manifest.read_text())['dependencies']
    record, = [r for r in records if r['distribution'] == name]
    assert record['dependency_revision'] == record['artifact_revision'] == revision
    wheel = manifest.parent / record['wheel']
    assert wheel.resolve().is_relative_to(manifest.parent.resolve())
    assert installed.version == record['version']
    assert direct['url'] == wheel.resolve().as_uri()
    assert 'archive_info' in direct and 'vcs_info' not in direct
    # uv records local wheels with empty archive_info; hash the exact verified
    # fixture rather than inventing VCS provenance for a wheel installation.
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == record['sha256']


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
            assert_private_provenance(name, revision)
            pins[name] = revision
    assert {'auth-service', 'controlplane-core', 'controlplane-db', 'controlplane-identity', 'controlplane-tenancy'} <= pins.keys()


def test_flags_are_opt_in_by_default(monkeypatch):
    from controlplane_identity.account_lifecycle import enforcement_enabled
    monkeypatch.delenv('ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED', raising=False)
    assert enforcement_enabled() is False


@pytest.mark.parametrize('tamper', ['none', 'digest', 'revision', 'url'])
def test_fixture_provenance_remains_bound_to_exact_wheel(tmp_path, monkeypatch, tamper):
    from types import SimpleNamespace
    wheel = tmp_path/'example-0.1.0-py3-none-any.whl'
    wheel.write_bytes(b'provenance test fixture')
    record = dict(distribution='example', version='0.1.0',
                  dependency_revision='a'*40, artifact_revision='a'*40,
                  wheel=wheel.name, sha256=hashlib.sha256(wheel.read_bytes()).hexdigest())
    direct = dict(url=wheel.as_uri(), archive_info={})
    if tamper == 'digest': record['sha256'] = 'b'*64
    if tamper == 'revision': record['dependency_revision'] = 'b'*40
    if tamper == 'url': direct['url'] = (tmp_path/'other.whl').as_uri()
    manifest = tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'dependencies': [record]}))
    monkeypatch.setenv('DEPENDENCY_FIXTURE_MANIFEST', str(manifest))
    monkeypatch.setitem(assert_private_provenance.__globals__, 'distribution',
                        lambda _: SimpleNamespace(version='0.1.0', read_text=lambda _: json.dumps(direct)))
    if tamper == 'none': assert_private_provenance('example', 'a'*40)
    else:
        with pytest.raises(AssertionError): assert_private_provenance('example', 'a'*40)
