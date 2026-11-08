# User-owned network and organization authority

`USER_SCOPED_AUTHORITY_REQUIRED=1` activates current, subject-bound authority.
The configured network administrator is a platform identity, not a tenant role.
Organization administration and billing are separate membership capabilities.
A network or tenant administrator cannot spend an organization's money without
its explicit billing membership. Disabled identities, inactive tenants and revoked
memberships are refused even when a signed session contains old role claims.

## Owner HTTP contract

`POST /api/v1/authority/check` uses the actor's normal verified bearer token.
There is no body subject or service-key impersonation mechanism. Send
`X-Tenant-ID` matching the verified tenant for all tenant-bound actions.

```json
{
  "version": 1,
  "request_id": "8bdb1029-6c45-4c4c-bba4-63037cfe41d8",
  "action": "lease.purchase",
  "tenant_id": "8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d",
  "organization_id": "6e5ea9b8-0a17-56a2-8b33-ef4797ca2b04"
}
```

The response echoes the full request and adds the verified `subject` and boolean
`allowed`. Consumers must match the nonce, action, subject and all target fields,
require boolean true, refuse redirects, verify TLS and fail closed on unavailable
or malformed responses. Responses have `Cache-Control: no-store`; do not reuse
an authorization decision across mutations or lease payment operations.

Actions: `network.admin` takes only `network`; `tenant.admin` and
`approval.resolve` take only `tenant_id`; `organization.read`,
`organization.admin` and `lease.purchase` take tenant and organization IDs.
A body cannot request a tenant different from its signed tenant context.
This contract does not confer human assurance or bypass approval-specific checks.

Organization member administration is under
`/api/v1/organizations/{organization_id}/members`. GET lists current memberships;
POST and PUT create/update a configured tenant profile's org membership; DELETE
revokes only that membership. The member document includes `user_id`, `role`
(`admin` or `member`) and strict boolean `can_purchase_leases`. These endpoints
cannot create network/tenant authority, revive disabled identities, or transfer
an unrelated organization's identity. Tenant-level role/group APIs require current
tenant administration; an org admin's role is not a tenant-wide admin role.

## Fresh TEST bootstrap

The Infra repository owns `config/test-fixtures.json`. The bootstrap consumes its
exact SHA-256 and a provider inventory with issuer, generation and every configured
account's actual UUID, email and enabled state. Provider inventory must come from
the new identity provider; a test-generated inventory is not live acceptance.

Install the separate immutable `0001_owner_schema` bundle under the nonprivileged
User schema owner, then run `python -m user_service.authority_migrate` with a private
`--database-url-file`. The additive migration verifies the exact baseline and
records its own resource digest; replay with different bytes is refused.

Run `python -m user_service.fixture_bootstrap --help` for explicit generation,
manifest, provider inventory, source SHA, private database URL and receipt paths.
The seed is one transaction and refuses an existing tenant, platform identity or
fixture generation. It never repairs a running account's role. Network admins
receive no implicit tenant profile. Hosting resolves to the configured host owner's
organization; login/enrollment cannot create replacement organizations or roles.

Runtime credentials must be separate from bootstrap/migration credentials. They
must not own/create schema objects, inherit privileged roles, or modify configured
network, tenant-binding, fixture or host-owner grants. FORCE RLS is required.
`USER_TEST_FIXTURE_GENERATION`, `USER_TEST_FIXTURE_SHA256` and the image's `GIT_SHA`
bind readiness to the seeded generation. Bootstrap credentials are not mounted in
the runtime. Normal org membership administration remains available within scope.

Seeding, image publication, isolated caller qualification, shared TEST cutover and
fresh native host qualification are separate gates. The owner seed receipt is not
a deployment receipt or evidence of host certification. Infra must bind its final
acceptance receipt to actual owner images and the staged database cluster identity.

`POST /authority/billing-context` resolves one current billing organization for the
verified caller and returns its canonical User identity ID. It accepts a tenant,
nonce and optional explicit organization selector, never a body subject. Missing
billing authority is 403; an unselected ambiguous org is 409. This is for new
spending, not settlement of existing obligations.

`POST /authority/identity-context` returns the canonical User identity within a
currently authorized tenant context without requiring an active billing org.
Disabled identities, inactive tenants, current user bans and wrong-network
contexts are refused. This lets consumers verify ownership of existing leases or
payments after an org billing grant is revoked. Consumers still compare the
canonical ID or recorded subject against their own durable resource ownership.

Scoped operator endpoints require the current administrator of the tenant's
network. A retained operator permissions claim or an org/tenant role label cannot
substitute for that network grant. Checks retain the verified target tenant scope
for subsequent operator directory and ban operations. Runtime readiness follows
both inherited and settable role chains, including mixed paths with SET FALSE
on an inherited table owner.
