#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC SKIP_TESTCONTAINERS
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv lock --check
uv sync --frozen --python 3.13
# Do not accept an unavailable Docker daemon as successful native qualification.
docker info >/dev/null
uv run --frozen pytest --junitxml="$scratch/source.xml"
uv build --out-dir "$scratch/dist"
python3 scripts/verify_wheel.py "$scratch/dist"
uv export --frozen --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
uv pip install --python "$scratch/venv/bin/python" --no-deps "$scratch"/dist/*.whl
mkdir -p "$scratch/owner"
cp -R core/user-service/tests core/user-service/scripts "$scratch/owner/"
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function --junitxml="$scratch/wheel.xml" owner/tests)
uv run --frozen python - "$scratch" <<'PY'
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
