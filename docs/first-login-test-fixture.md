# First-login TEST fixture owner contract

`python -I -m user_service.first_login_fixture prepare|restore` is an owner
operator entry point, never an HTTP route or runtime capability. Infra owns its
checked-in definition, session/browser lifecycle, deployment fence and invocation.
Do not invoke it on shared TEST until that Infra lifecycle is committed and the
qualified runtime containing this module is deployed.

The operation accepts the original canonical manifest and provider-subject
inventory, and only its enabled `unassociated` actor with no grants, spending or
host capability. It verifies the installed immutable generation, manifest and
subject hashes, nonprivileged User schema owner and exact canonical profile IDs
and baseline roles. Other fixture identities, scopes, grants, seed markers,
provider identities and host records are never changed.

Preparation retains the exact original platform and tenant rows and declaration
mapping in an exclusive, fsynced, mode-0600 journal in an operator-owned private
directory before removing those rows in one transaction. It serializes owner
writes, checks every configured RLS scope for dependent actor/profile state, and
refuses external-schema references. It never cascades dependent state. The normal
verified issuer login then creates its individual, roleless profiles through
`/api/v1/authority/login-tenant`.

Restoration uses the retained journal bound to the same database/schema OIDs,
generation, subject inventory and issuer. It accepts either no newly created
profiles or exactly the expected roleless pair with no dependent state, and
restores the original rows and declaration atomically. Repeated restoration is a
verified no-op. A durable journal with a rolled-back preparation can also be
restored safely. An unexpected role, dependent record, missing journal or changed
binding refuses without reconstruction; retain the journal for investigation.
Never use bootstrap, account closure or a direct SQL repair for recovery.

Required operator environment: `USER_TEST_FIRST_LOGIN_ENABLED=1`,
`USER_TEST_FIXTURE_GENERATION`, `USER_TEST_FIXTURE_SHA256`, `KEYCLOAK_ISSUER` and
`USER_FIXTURE_DATABASE_URL` selecting the existing nonprivileged schema owner.
Keep that connection and journal private, outside ordinary runtime configuration.
Required arguments are `--manifest`, `--subjects` and `--journal`. Output contains
only restoration/change booleans. Infra must first verify canonical readiness,
serialize shared acceptance and invalidate existing sessions through Auth; after
normal login and refusal probes it must log out, restore, verify readiness and
all three paused host bindings, then remove its private temporary login material.
Preserve the journal until successful restoration has been independently verified.
This owner contract alone is not shared deployment or live acceptance evidence.
