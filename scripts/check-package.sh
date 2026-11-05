#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC SKIP_TESTCONTAINERS DEPENDENCY_FIXTURE_MANIFEST
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
sync_options=()
run_options=()
export_options=()
fixture_wheels=()
case "${1:-}" in
  '') uv lock --project core/user-service --check ;;
  --fixtures)
    fixture_paths=$(python3 core/user-service/scripts/verify_dependency_fixtures.py "$PWD/core/user-service")
    mapfile -t fixture_wheels <<< "$fixture_paths"
    export DEPENDENCY_FIXTURE_MANIFEST="$PWD/core/user-service/tests_artifacts/dependencies/manifest.json"
    run_options=(--no-sync)
    sync_options+=(--no-install-package controlplane-api)
    export_options+=(--no-emit-package controlplane-api)
    sync_options+=(--no-install-package controlplane-tenancy)
    export_options+=(--no-emit-package controlplane-tenancy)
    sync_options+=(--no-install-package controlplane-identity)
    export_options+=(--no-emit-package controlplane-identity)
    sync_options+=(--no-install-package controlplane-db)
    export_options+=(--no-emit-package controlplane-db)
    sync_options+=(--no-install-package controlplane-events)
    export_options+=(--no-emit-package controlplane-events)
    sync_options+=(--no-install-package operator-ban-store)
    export_options+=(--no-emit-package operator-ban-store)
    sync_options+=(--no-install-package controlplane-core)
    export_options+=(--no-emit-package controlplane-core)
    sync_options+=(--no-install-package auth-service)
    export_options+=(--no-emit-package auth-service)
    sync_options+=(--no-install-package spanopticon-models)
    export_options+=(--no-emit-package spanopticon-models)
    sync_options+=(--no-install-package spanopticon-tests)
    export_options+=(--no-emit-package spanopticon-tests)
    ;;
  *) echo 'Usage: bash scripts/check-package.sh [--fixtures]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then echo 'Unexpected arguments' >&2; exit 2; fi
uv sync --project core/user-service --frozen --python 3.13 "${sync_options[@]}"
if (( ${#fixture_wheels[@]} )); then
  uv pip install --python core/user-service/.venv/bin/python --no-deps --reinstall "${fixture_wheels[@]}"
fi
# Do not accept an unavailable Docker daemon as successful native qualification.
docker info >/dev/null
uv run --project core/user-service --frozen "${run_options[@]}" pytest core/user-service/tests --junitxml="$scratch/source.xml"
uv run --project core/user-service --frozen "${run_options[@]}" pytest -q core/user-service/tests_tools
uv build core/user-service --out-dir "$scratch/dist"
python3 scripts/verify_wheel.py "$scratch/dist"
uv export --project core/user-service --frozen "${export_options[@]}" --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
uv pip install --python "$scratch/venv/bin/python" --no-deps "${fixture_wheels[@]}" "$scratch"/dist/*.whl
mkdir -p "$scratch/owner"
cp -R core/user-service/tests core/user-service/scripts "$scratch/owner/"
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function --junitxml="$scratch/wheel.xml" owner/tests)
uv run --project core/user-service --frozen "${run_options[@]}" python - "$scratch" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
with tarfile.open(next((root / 'dist').glob('*.tar.gz'))) as archive:
    archive.extractall(root / 'sdist', filter='data')
PY
uv build --wheel "$scratch"/sdist/* --out-dir "$scratch/rebuilt"
python3 scripts/verify_wheel.py "$scratch/rebuilt"
uv pip install --python "$scratch/venv/bin/python" --no-deps --reinstall "$scratch"/rebuilt/*.whl
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function --junitxml="$scratch/sdist.xml" owner/tests)
python3 - "$scratch" <<'PY'
import pathlib, sys, xml.etree.ElementTree as ET
for path in pathlib.Path(sys.argv[1]).glob('*.xml'):
    root = ET.parse(path).getroot()
    assert not list(root.iter('skipped')), f'Native qualification skipped cases: {path.name}'
PY
# Local/container qualification can retain exactly the tested service artifacts.
if [[ -n "${SERVICE_ARTIFACT_DIR:-}" ]]; then
  mkdir -p "$SERVICE_ARTIFACT_DIR"
  cp "$scratch/dist"/* "$SERVICE_ARTIFACT_DIR/"
fi
