from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_retained_review_runs_after_publication_with_read_only_access():
    service = (ROOT / '.github/workflows/service.yml').read_text()
    job = service.split('  retained-images:', 1)[1]
    assert 'needs: service' in job
    assert 'packages: read' in job and 'packages: write' not in job
    assert 'uses: ./.github/workflows/historical-images.yml' in job
    workflow = (ROOT / '.github/workflows/historical-images.yml').read_text()
    assert '  workflow_call:' in workflow and '  pull_request:' in workflow
    assert "REQUIRE_REGISTRY_INVENTORY: '1'" in workflow
    assert 'max-parallel: 4' in workflow
    assert 'upload-artifact' not in workflow
    assert 'docker run' not in (ROOT / 'scripts/check-older-image.sh').read_text()
