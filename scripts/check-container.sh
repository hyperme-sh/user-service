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
docker build --secret "id=dependency_read_token,src=$DEPENDENCY_READ_TOKEN_FILE" \
  -f core/user-service/Dockerfile -t "$image" .
docker run --rm --network none "$image" /app/.venv/bin/python -I -c '
import os, user_service.app, user_service.closure_authority, user_service.closure_daemon
from controlplane_identity.account_lifecycle import enforcement_enabled
assert not enforcement_enabled()
assert not any(name in os.environ for name in ("DEPENDENCY_READ_TOKEN", "ACCOUNT_CLOSURE_WORKER_ENABLED"))
assert os.geteuid() == 65532
'
uv run --frozen python scripts/check-container.py "$image"
