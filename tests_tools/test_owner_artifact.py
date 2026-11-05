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
