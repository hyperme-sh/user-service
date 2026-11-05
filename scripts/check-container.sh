#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEPENDENCY_READ_TOKEN_FILE:?Provide an existing read-only GitHub token file for BuildKit}"
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
docker build --build-arg "GIT_SHA=$build_sha" --build-arg "BUILT_AT=$built_at" --secret "id=dependency_read_token,src=$DEPENDENCY_READ_TOKEN_FILE" \
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
uv run --project core/user-service --frozen python scripts/check-container.py "$image" "$build_sha"
