# Startup person and organizations

The optional internal startup API consumes a private server-side configuration
file through `STARTUP_IDENTITY_CONFIG_FILE` and requires
`STARTUP_IDENTITY_ENABLED=1`. Infra #882 owns its schema and isolated fixture.
No identity values or credentials belong in templates. Apply the explicit
`python -m user_service.startup_migrate --database-url-file FILE` migration
using the existing nonprivileged schema owner before enabling the API.
The existing active tenant and its network assignment must already exist.

POST `/api/v1/internal/startup/reconcile` with a `USER_STARTUP_TOKEN` bearer
credential and `{ "mapping_sha256": "..." }`. User creates one person and the
three configured organizations in one transaction, with a tenant-scoped lock.
The immutable Entra tuple identifies the person; email only detects conflicts.
Owner records and existing admin memberships are explicit per organization.
No platform grants are written here. Existing changed or disabled memberships
cause a conflict rather than automatic privilege restoration.

POST `/api/v1/internal/startup/status` with `USER_STARTUP_READ_TOKEN` (or the
writer credential) validates and returns the stored mapping without creating
it. Auth alone calls `/bind` with `AUTH_IDENTITY_OWNER_TOKEN`, the same mapping
hash and the expected opaque `subject`. Binding preserves an existing subject;
a new broker uses the chosen person ID. Email never supplies a broker subject.
Keep read, reconciliation and Auth binding credentials distinct.

The small additive identity contract is copied byte-for-byte from the source
revision recorded in `startup_contract_source.json`. Its digest is checked by
unit tests. This avoids changing transitive dependency pins or package versions.
The migration and contract are included in the existing wheel/sdist consumers.
Transaction, concurrency, rollback, conflict and tenant isolation cases are
part of the owner CI suite; agents do not run them manually. The central
scheduled batch consumes the same owner suite from main.


The deployment envelope embeds Infra's canonical `binding` and its verified
`binding_sha256`, with separate `owner` metadata for the existing tenant/network,
profile email and Keycloak issuer/audience. Organizations use the declared IDs
and role lists. The current User authority supports one owner tenant; a mapping
containing an organization from another tenant is rejected before database work.
The existing organization membership table remains authoritative. The additive
owner relation records explicit ownership without a second role store.
