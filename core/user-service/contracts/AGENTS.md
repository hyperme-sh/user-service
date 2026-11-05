# Operator ban contract context

User-service owns this read-only package and operator_bans. Keep imports of
user_service, api and product implementations out of the package. Only boolean
predicates cross the public interface. Preserve explicit tenant and lifted-row
filters, caller sessions/locks and RLS authority; never commit or change roles.
Public module: operator_ban_store. Package versions follow the shared release line; source and transport
contract identities remain distinct. Test PostgreSQL/RLS, installed wheel and
owning user-service, shared and Hypermesh suites. Tables and migrations stay
with their existing owner.

Hosted pull-request contract checks may run on disposable Ubuntu with contents
read-only, a disposable PostgreSQL service and verified dependency-wheel fixtures.
They receive no private dependency or deployment credentials. Existing main
contract and full-service runner policies remain unchanged.
