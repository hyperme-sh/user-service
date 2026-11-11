#!/usr/bin/env bash
# Retry only the registry's missing-blob response with the same local image.
set -euo pipefail
image="${1:?Qualified image reference required}"
log=$(mktemp)
trap 'rm -f -- "$log"' EXIT
for attempt in 1 2 3; do
  if docker push "$image" >"$log" 2>&1; then
    cat "$log"
    exit 0
  else
    status=$?
  fi
  cat "$log" >&2
  if ! grep -Fxq 'unknown blob' "$log" || [[ "$attempt" == 3 ]]; then
    exit "$status"
  fi
  sleep "$((attempt * 5))"
done
