# Additive TEST fixture topology

`python -m user_service.fixture_topology plan --previous PREDECESSOR --desired DESIRED`
accepts only the configured s3r.ch TEST tenant addition. Every existing account,
grant, network, organization and host declaration must be unchanged. This uses
#75's owner insertion contract; it never calls bootstrap on an existing database.

The infrastructure operator supplies an immutable owner artifact, its exact source
revision, an operation UUID and the existing private User schema-owner URL file:

```
python -m user_service.fixture_topology apply --previous PREDECESSOR --desired DESIRED \
  --operation-id UUID --source-sha OWNER_REVISION --database-url-file PRIVATE_FILE
```

The transaction verifies the nonprivileged schema owner, locks the existing
fixture generation and checks all live tenant/network bindings. It journals the
operation and successor manifest atomically with insertion. Existing identity and
grant rows are observed under explicit RLS scopes and remain unchanged. The
original seed source, subject digest and seed timestamp are preserved. The journal
records this transition's source separately; no old observation is relabeled.

An interrupted uncommitted transaction rolls back. Repeating a committed apply
returns the same journal receipt after verifying the current topology. An operation
UUID cannot be reused for different source/configuration or reapplied after rollback.

Use the same arguments with `rollback` only before the new tenant is consumed.
Rollback locks owner tenant tables, refuses any new business rows or changed
metadata, removes only the exact inserted role/group/tenant metadata and its event
registry entry, and restores the predecessor manifest marker. It never deletes
existing tenant data or changes users, memberships, credentials or privileges.
A rolled-back journal remains retained; retrying rollback is a no-op.

The returned receipt is an actual owner transaction observation, not runtime
acceptance. Infra must independently preserve predecessor files, update Auth/User
scope configuration, remeasure the running owners and closed host guard, and
collect fresh HTTP/browser/host acceptance. No deployment, reset, reseed, version
advance, tag or release is performed by this command.
