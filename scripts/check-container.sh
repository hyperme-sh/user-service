#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
secret_args=()
if [[ -n "${DEPENDENCY_READ_TOKEN_FILE:-}" ]]; then
  [[ -r "$DEPENDENCY_READ_TOKEN_FILE" ]] || { echo "Dependency credential file is not readable" >&2; exit 1; }
  secret_args=(--secret "id=dependency_read_token,src=$DEPENDENCY_READ_TOKEN_FILE")
fi
image="user-service-closure:qualification-$$"
container=""
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null; fi
  docker image rm "$image" >/dev/null
}
trap cleanup EXIT
# Pass only the secret path. Docker mounts its bytes for one builder command.
build_sha=$(git rev-parse HEAD)
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker build --build-arg "GIT_SHA=$build_sha" --build-arg "BUILT_AT=$built_at" "${secret_args[@]}" \
  -f core/user-service/Dockerfile -t "$image" .
docker run --rm --network none "$image" /app/.venv/bin/python -I -c '
import os, user_service.app, user_service.closure_authority, user_service.closure_daemon
import user_service.password_reset_authority
assert user_service.password_reset_authority.create_app().openapi_url is None
from controlplane_identity.account_lifecycle import enforcement_enabled
assert not enforcement_enabled()
assert not any(name in os.environ for name in ("DEPENDENCY_READ_TOKEN", "ACCOUNT_CLOSURE_WORKER_ENABLED"))
assert os.geteuid() == 65532
'
uv run --project core/user-service --frozen --no-sync python scripts/check-container.py "$image" "$build_sha"

# Preserve the exact runtime only after all container qualification succeeds.
# Infra imports these bytes into ACR; it must never rebuild a release candidate.
if [[ -n "${TESTED_IMAGE_DIR:-}" ]]; then
  mkdir -p "$TESTED_IMAGE_DIR"
  docker save "$image" -o "$TESTED_IMAGE_DIR/image.tar"
  printf '%s\n' "$image" > "$TESTED_IMAGE_DIR/image.ref"
  sha256sum "$TESTED_IMAGE_DIR/image.tar" | cut -d ' ' -f 1 > "$TESTED_IMAGE_DIR/image.sha256"
fi

if [[ -n "${QUALIFIED_IMAGE_REF:-}" ]]; then
  docker tag "$image" "$QUALIFIED_IMAGE_REF"
fi
