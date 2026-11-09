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

## Service deployments and binary provenance

Each TEST service automatically tracks the latest PR merged into its repository's default branch. Deploy the tested build through a moving TEST channel. Do not pin running services to versions, commit SHAs or image digests, require manual pin updates, or require peer services to run matching builds. Preserve patch compatibility, including during early development, and verify it through the service contract.

Use exact versions and digests for downloadable bundles and to record or verify which binary was built, tested or released. A running service may report its revision for diagnostics. Production follows its existing promotion policy and explicit release authorization.
