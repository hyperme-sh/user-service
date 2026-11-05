# Operator ban owner contract

User-service owns the operator ban table and this separately installable,
read-only package. Trusted server callers use `operator_ban_store.active_ban`
for async user/group/device checks and `subject_banned_sync` for a single
subject on a caller connection. Only a boolean crosses the interface.

Queries filter the tenant and active (unlifted) row explicitly, including when
the caller bypasses RLS. The package preserves the caller transaction and RLS
privileges. Database errors propagate so consuming guards retain their existing
fail-closed behavior. No cache, service application dependency, schema migration,
provider call or ban write is included.

The package follows the shared 0.24 release line. The `operator-ban-store-v0`
source interface remains unchanged and is independent of transport wire versions.

Run `bash scripts/check-package.sh` with a disposable `TEST_DATABASE_URL` for
source, installed-wheel and rebuilt-sdist PostgreSQL/RLS consumers. Hosted PR
checks use `--fixtures` with a verified published database wheel; the manifest
binds it to the declared immutable pin and frozen lock. Fixtures are test-only
and excluded from distributions. Main retains its scoped private-dependency
installation path. Full user-service and downstream integrations have separate
qualification; this library does not establish their acceptance.
