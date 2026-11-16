# Private account-status reader

`user_service.account_status_reader:app` packages the existing authenticated
account check as a separate, default-off process. It does not import the closure
worker or expose mutation routes. The full mutation authority is unchanged.

Required deployment inputs:

- `ACCOUNT_STATUS_READER_ENABLED=true` only at separately authorized installation.
- `ACCOUNT_STATUS_DATABASE_URL`: protected credential for a dedicated reader.
- `ACCOUNT_STATUS_DATABASE_ROLE` and `ACCOUNT_STATUS_DATABASE_SCHEMA`: explicit
  expected role and first schema, set in the role's search path.
- Existing owner guard-token and API-key status configuration for the native check.

The role must default to read-only transactions, have no privileged attributes or
role memberships, no table/column mutation grants, no schema/database CREATE,
and no executable user-defined SECURITY DEFINER functions. Both account status
and identity retirement tables must be visible with full SELECT and without RLS
filtering; missing or filtered data is a refusal, never an empty successful read.
Database tables and grants are provisioned through the owning migration process,
not at application startup. `/internal/ready` repeats qualification and requires
the same owner authentication as the account check. Operational errors are opaque.

Infra #1245 must record this role and its two source tables in the canonical
backup and restore declaration, with role settings/grants restored before the
service starts. Expose only the private TLS route; publish no container port to
the public network. The service follows its normal moving TEST channel. This
source change installs nothing and enables no flags. Existing enforcement,
worker, actions and authority settings remain unchanged.

PR validation uses mocked role/connection and route contracts. Database grants,
TLS and composed caller checks belong in registered CI, not manual host checks.
