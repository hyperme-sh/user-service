# Operator ban contract context

User-service owns this read-only package and operator_bans. Keep imports of
user_service, api and product implementations out of the package. Only boolean
predicates cross the public interface. Preserve explicit tenant and lifted-row
filters, caller sessions/locks and RLS authority; never commit or change roles.
Public module: operator_ban_store. Contract/source version is independent of
the six shared inversion libraries. Test PostgreSQL/RLS, installed wheel and
owning user-service, shared and Hypermesh suites. Tables and migrations stay
with their existing owner.
