import importlib.util
import io
from pathlib import Path
import zipfile

import pytest

spec = importlib.util.spec_from_file_location('owner', Path(__file__).resolve().parents[1]/'scripts/owner_artifact.py')
owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)


def wheel(directory, distribution, version='0.1.0', runtime=b'pass\n'):
    package = owner.PACKAGES[distribution]
    path = directory/f'{package}-{version}-py3-none-any.whl'
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr(f'{package}/__init__.py', runtime)
        z.writestr(f'{package}-{version}.dist-info/METADATA', f'Name: {distribution}\nVersion: {version}\n')
    return path


def pair(directory):
    for distribution in owner.PACKAGES:
        wheel(directory, distribution)


def test_exact_bytes_are_deterministic_and_both_runtimes_covered(tmp_path):
    pair(tmp_path)
    first = owner.build(tmp_path).read_bytes()
    assert owner.build(tmp_path).read_bytes() == first
    contract, evidence = owner.inspect(first)
    wheel(tmp_path, 'operator-ban-store', runtime=b'changed\n')
    changed, different = owner.inspect(owner.build(tmp_path).read_bytes())
    assert contract != changed and evidence['artifact_sha256'] != different['artifact_sha256']


@pytest.mark.parametrize('case', ['missing', 'extra', 'mixed', 'filename', 'identity', 'unsafe', 'duplicate'])
def test_invalid_owner_bundle_rejected(tmp_path, case):
    pair(tmp_path)
    if case == 'missing': next(tmp_path.glob('user_service*')).unlink()
    elif case == 'extra': (tmp_path/'extra.whl').write_bytes(b'bad')
    elif case == 'mixed':
        next(tmp_path.glob('user_service*')).unlink(); wheel(tmp_path, 'user-service', '0.24.0')
    elif case == 'filename': next(tmp_path.glob('user_service*')).rename(tmp_path/'user_service-0.24.0-py3-none-any.whl')
    else:
        path = next(tmp_path.glob('user_service*'))
        with zipfile.ZipFile(path, 'a') as z:
            if case == 'identity': z.writestr('user_service-0.1.0.dist-info/METADATA', 'Name: wrong\nVersion: 0.1.0\n')
            elif case == 'unsafe': z.writestr('user_service/../escape', b'bad')
            else: z.writestr('user_service/__init__.py', b'bad')
    with pytest.raises(ValueError): owner.build(tmp_path)


def test_outer_duplicate_rejected(tmp_path):
    pair(tmp_path)
    path = owner.build(tmp_path)
    with zipfile.ZipFile(path, 'a') as z:
        z.writestr(z.namelist()[0], b'bad')
    with pytest.raises(ValueError): owner.inspect(path.read_bytes())


def test_current_source_qualification_does_not_rewrite_prior_candidate(tmp_path):
    import json
    from test_release_candidate import verifier
    pair(tmp_path)
    archive = owner.build(tmp_path)
    old = tmp_path / 'historical'
    owner.qualify(archive, old, 'a' * 40)
    retained = {p.name: p.read_bytes() for p in old.iterdir()}
    wheel(tmp_path, 'user-service', runtime=b'new configured host enrollment\n')
    archive = owner.build(tmp_path)
    current = tmp_path / 'current'
    owner.qualify(archive, current, 'b' * 40)
    verifier.verify(current / 'release.json', current / 'contract.json', current / 'evidence.json', 'user-service')
    manifest = json.loads((current / 'release.json').read_text())
    assert manifest['source_sha'] == 'b' * 40
    assert manifest['stable_release'] is False and manifest['purpose'] == 'artifact-qualification'
    assert {p.name: p.read_bytes() for p in old.iterdir()} == retained
    with pytest.raises(ValueError, match='artifact differs'):
        verifier.verify(old / 'release.json', current / 'contract.json', current / 'evidence.json', 'user-service')
    with pytest.raises(FileExistsError):
        owner.qualify(archive, current, 'c' * 40)


def test_qualification_requires_source_before_writing(tmp_path):
    pair(tmp_path)
    with pytest.raises(ValueError, match='source revision'):
        owner.qualify(owner.build(tmp_path), tmp_path / 'invalid', 'main')
    assert not (tmp_path / 'invalid').exists()


def test_qualification_stays_outside_flat_publisher_inventory(tmp_path):
    dist = tmp_path / 'dist'
    dist.mkdir()
    pair(dist)
    archive = owner.build(dist)
    qualification = tmp_path / 'qualification'
    owner.qualify(archive, qualification, 'a' * 40)
    (dist / 'runtime-image.json').write_text('{"isolated_fixture":true}')
    owner.verify_delivery(dist)
    assert not (dist / 'qualification').exists()
    assert (qualification / 'release.json').is_file()
    # Reproduce the old upload layout: strict producer validation must refuse.
    (dist / 'qualification').mkdir()
    (dist / 'qualification' / 'contract.json').write_text('{}')
    with pytest.raises(ValueError, match='flat regular files'):
        owner.verify_delivery(dist)


@pytest.mark.parametrize('case', ['empty', 'symlink', 'reserved', 'invalid'])
def test_publisher_inventory_refuses_unsafe_entries(tmp_path, case):
    if case == 'symlink':
        (tmp_path / 'target.whl').write_bytes(b'fixture')
        (tmp_path / 'link.whl').symlink_to('target.whl')
    elif case == 'reserved':
        (tmp_path / 'release-manifest.json').write_text('{}')
    elif case == 'invalid':
        (tmp_path / 'bad name.whl').write_bytes(b'fixture')
    with pytest.raises(ValueError, match='flat regular files'):
        owner.verify_delivery(tmp_path)


def test_pr_and_main_retention_separate_qualification_from_delivery():
    root = Path(__file__).resolve().parents[1]
    for name in ('preparation', 'service'):
        workflow = (root / '.github/workflows' / (name + '.yml')).read_text()
        assert 'qualified="$OWNER_QUALIFICATION_DIR"' in workflow
        assert 'qualified="$SERVICE_ARTIFACT_DIR/qualification"' not in workflow
        assert 'name: owner-qualification' in workflow
        assert 'path: ${{ env.OWNER_QUALIFICATION_DIR }}/*' in workflow
        assert 'verify-delivery "$SERVICE_ARTIFACT_DIR"' in workflow
        assert '- name: Retain validated owner artifacts' not in workflow
        assert 'name: tested-dist' not in workflow
        assert 'name: prepared-dist' not in workflow
        assert workflow.index('verify-delivery "$SERVICE_ARTIFACT_DIR"') < workflow.index('name: owner-qualification')
