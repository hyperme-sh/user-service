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

The `operator-ban-store-v0` source contract is version 0.1.0, separate from the
six shared inversion libraries and the control-plane 0.8.0 wire contract.
