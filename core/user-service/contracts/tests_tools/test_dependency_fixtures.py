import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dependency_fixture', ROOT/'scripts/verify_dependency_fixtures.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def root(tmp_path):
    shutil.copytree(ROOT/'tests_artifacts', tmp_path/'tests_artifacts')
    for name in ['pyproject.toml', 'uv.lock']:
        shutil.copyfile(ROOT/name, tmp_path/name)
    return tmp_path


def test_real_published_fixtures_match_pins(root):
    assert module.verify(root)


def test_tampered_artifact_fails(root):
    wheel = module.verify(root)[0]
    wheel.write_bytes(wheel.read_bytes() + b'tampered')
    with pytest.raises(ValueError, match='digest'):
        module.verify(root)


@pytest.mark.parametrize('name', ['pyproject.toml', 'uv.lock'])
def test_changed_pin_requires_matching_artifact(root, name):
    record = json.loads((root/'tests_artifacts/dependencies/manifest.json').read_text())['dependencies'][0]
    p = root/name
    p.write_text(p.read_text().replace(record['dependency_revision'], 'a'*40))
    with pytest.raises(ValueError, match='dependency'):
        module.verify(root)


def test_missing_artifact_fails(root):
    module.verify(root)[0].unlink()
    with pytest.raises(FileNotFoundError):
        module.verify(root)


@pytest.mark.parametrize('change', ['escape', 'extra', 'version', 'source'])
def test_invalid_manifest_fails(root, change):
    p = root/'tests_artifacts/dependencies/manifest.json'
    record = json.loads(p.read_text())
    if change == 'escape': record['dependencies'][0]['wheel'] = '../escape.whl'
    if change == 'extra': record['dependencies'].append(record['dependencies'][0])
    if change == 'version': record['dependencies'][0]['version'] = '0.24.99'
    if change == 'source': record['dependencies'][0]['artifact_revision'] = 'b'*40
    p.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        module.verify(root)
