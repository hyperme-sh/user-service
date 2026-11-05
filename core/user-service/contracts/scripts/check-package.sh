#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC
: "${TEST_DATABASE_URL:?Disposable PostgreSQL is required}"
sync_options=()
run_options=()
export_options=()
fixture_wheels=()
case "${1:-}" in
  '') uv lock --check ;;
  --fixtures)
    fixture_paths=$(python3 scripts/verify_dependency_fixtures.py "$PWD")
    mapfile -t fixture_wheels <<< "$fixture_paths"
    run_options=(--no-sync)
    sync_options+=(--no-install-package controlplane-db)
    export_options+=(--no-emit-package controlplane-db)
    ;;
  *) echo 'Usage: bash scripts/check-package.sh [--fixtures]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then echo 'Unexpected arguments' >&2; exit 2; fi
uv sync --frozen --python 3.13 "${sync_options[@]}"
if (( ${#fixture_wheels[@]} )); then
  uv pip install --python .venv/bin/python --no-deps --reinstall "${fixture_wheels[@]}"
fi
uv run --frozen "${run_options[@]}" pytest
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv build --out-dir "$scratch/dist"
uv run --frozen "${run_options[@]}" python scripts/verify_wheel.py "$scratch/dist"
uv run --frozen "${run_options[@]}" pytest -q tests_tools
uv export --frozen "${export_options[@]}" --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
if (( ${#fixture_wheels[@]} )); then
  uv pip install --python "$scratch/venv/bin/python" --no-deps "${fixture_wheels[@]}"
fi
uv pip install --python "$scratch/venv/bin/python" --constraint "$scratch/requirements.txt" "$scratch"/dist/*.whl
cp -R tests "$scratch/"
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null tests)
# Rebuild from the sdist; a checkout must not supply omitted package files.
uv run --frozen "${run_options[@]}" python - "$scratch" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
with tarfile.open(next((root / 'dist').glob('*.tar.gz'))) as archive:
    archive.extractall(root / 'sdist', filter='data')
PY
uv build --wheel "$scratch"/sdist/* --out-dir "$scratch/rebuilt"
uv run --frozen "${run_options[@]}" python scripts/verify_wheel.py "$scratch/rebuilt"
uv pip install --python "$scratch/venv/bin/python" --no-deps --reinstall "$scratch"/rebuilt/*.whl
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null tests)

# Retain the exact validated bytes for the release channel; never rebuild them.
if [[ -n "${RELEASE_ARTIFACT_DIR:-}" ]]; then
  mkdir -p "$RELEASE_ARTIFACT_DIR"
  cp "$scratch/dist"/* "$RELEASE_ARTIFACT_DIR/"
fi
