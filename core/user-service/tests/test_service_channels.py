"""Shared service-reference and private closure configuration contracts."""
import hashlib
import json
import os
from pathlib import Path

import pytest
from user_service import service_channels
from user_service.closure_runtime import IMAGE_REPOSITORIES, check_image
from user_service.closure_worker import WorkerUnavailable

VECTORS = json.loads(Path(__file__).with_name('service-reference-vectors.json').read_text())


@pytest.mark.parametrize('image', VECTORS['accepted'])
def test_shared_accepted_references_are_preserved(image):
    assert service_channels.reference(image, VECTORS['repository']) == image


@pytest.mark.parametrize('image', VECTORS['rejected'])
def test_shared_rejected_references_fail_closed(image):
    with pytest.raises(ValueError):
        service_channels.reference(image, VECTORS['repository'])


@pytest.mark.parametrize('repository', IMAGE_REPOSITORIES)
@pytest.mark.parametrize('tag', ['test', 'main', '0.1.0', '0.1.0-test.2'])
def test_closure_configuration_roundtrip(monkeypatch, repository, tag):
    image = repository + ':' + tag
    monkeypatch.setenv('ACCOUNT_CLOSURE_IMAGE', image)
    assert check_image() == image
    assert os.environ['ACCOUNT_CLOSURE_IMAGE'] == image


@pytest.mark.parametrize('image', ['', 'ghcr.io/hyperme-sh/user-service',
    'ghcr.io/hyperme-sh/user-service:test\n',
    'ghcr.io/hyperme-sh/user-service:test@sha256:' + 'a' * 64,
    'https://ghcr.io/hyperme-sh/user-service:test',
    'user:secret@ghcr.io/hyperme-sh/user-service:test',
    'ghcr.io/hyperme-sh/user-service-other:test',
    'ghcr.io/hyperme-sh/user-service@sha256:' + 'a' * 64])
def test_closure_configuration_refuses_malformed_or_wrong_owner(monkeypatch, image):
    monkeypatch.setenv('ACCOUNT_CLOSURE_IMAGE', image)
    with pytest.raises(WorkerUnavailable):
        check_image()


def test_missing_image_refuses_startup(monkeypatch):
    monkeypatch.delenv('ACCOUNT_CLOSURE_IMAGE', raising=False)
    with pytest.raises(WorkerUnavailable):
        check_image()


def test_shared_parser_and_vectors_match_recorded_source():
    source = json.loads((Path(__file__).parents[1]/'scripts/service-channels-source.json').read_text())
    for path in (Path(service_channels.__file__), Path(__file__).with_name('service-reference-vectors.json')):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['sha256'][path.name]
