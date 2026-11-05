# User service operator bans

Database-backed operator-console ban operations use the caller's tenant-scoped
PostgreSQL rows, rather than the current worker's in-process ban book. A ban
created before a restart or by another worker therefore remains visible and
can be lifted through the console.

- Listing preserves tenant, subject-kind and subject-ID filters and includes
  lifted history.
- Creation validates the request using a fresh book, then relies on the
  persisted active-ban uniqueness constraint. Duplicate active bans return 409;
  a savepoint prevents that conflict from aborting the caller transaction.
- Lifting locks the matching active row in the session tenant, records actor,
  reason and time, and flushes without committing. A foreign-tenant, missing or
  already-lifted ban returns 404. Commit/rollback remain owned by the request.
- Portal group grants check the persisted active ban in the same transaction,
  so a restart does not accidentally restore a banned group's grants, and a
  committed lift becomes visible to later sessions.
- User-directory ban badges and soft-delete responses use persisted bans too.
  Directory pages load active bans in one tenant-scoped batch instead of a
  separate query for every user. Soft deletion does not lift an existing ban.

The existing in-memory console path remains for runs without a database session;
database-backed requests do not populate a second local authority. Existing
operator permission gates and asynchronous route offloading are preserved.
The read-only [operator-ban contract](contracts/README.md), wire payloads and
database ownership are unchanged.

This adopts the reviewed service repair from
[hyperme-sh/user-service PR #1](https://github.com/hyperme-sh/user-service/pull/1)
at `7954b2f9d3c7737526a059f0e27bebef982e4df6`, tracked in
[(s)panopticon #656](https://github.com/FyberLabs/panopticon/issues/656).
Disposable PostgreSQL regressions cover empty process state, independent
sessions, tenant denial, rollback, repeated lifts, duplicate bans and re-bans.
These checks do not establish deployed acceptance or lift any real host/user ban.
Deployment must separately verify the console against its owning database.


## Private account closure worker

`python -m user_service.closure_worker --max-jobs 10` processes at most ten due
native lifecycle claims and exits. It is default-off: both
`ACCOUNT_CLOSURE_WORKER_ENABLED=true` and
`ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED=true` are required. It consumes already
verified native closure requests; pending intake and email text are not executable
closure authority.

Run it in a private process using `ACCOUNT_CLOSURE_WORKER_DATABASE_URL` with the
`postgresql+asyncpg` driver and a role that can read all lifecycle scopes and
execute the private owner functions. Startup rejects tenant-only/RLS-filtered
roles and incomplete native producer installations. It neither migrates the
schema nor falls back to the public service's database URL. Its Keycloak client
is the dedicated `account-closure-worker`; existing exact-issuer, protected-user
and credential-separation checks apply. Configure its Keycloak URL, realm, client
ID and secret, distinct guard/operations tokens, keys and Hypermesh owner URLs,
and the configured gateway destinations. Keep the writer credential and global
database role out of the public user-service process.

The worker renews claims during owner requests, cancels work when authority is
lost, and releases owned claims on cancellation or SIGTERM. Owner failures retain
sanitized retry codes; a retry preserves previously committed receipts and
running leases. PostgreSQL supplies retry and retention times. The command emits
no customer identities, provider responses or database credentials.

After personal erasure, the command also runs native payer-risk expiry. It
removes only unreserved records whose native seven-year clocks have expired;
unknown dates and preservation holds remain protected. Every attempt rescans
the native source and records its current epoch, without caching a zero across
new evidence. Accounts with no remaining native financial sources can finish only after every
installed owner supplies a fresh zero at the same epoch. The initial completion
path also requires no renter-contract history and no remaining creator/routing
references; even a zero-allocation legacy budget keeps the account pending.
Completion removes cleanup resource IDs and counters while retaining minimal
identity/credential retirement aliases and admission fences. Other financial
owner cleanup, private scheduler/deployment wiring and full acceptance remain required
for #369. No deployment manifest enables the worker in this change.

For a continuously supervised private process, use
`python -m user_service.closure_daemon --max-jobs 10 --poll-seconds 30`.
It repeats bounded batches, closes clients and pools between ticks, and repeats
configuration, role and native installation checks. Poll intervals are limited
to 5–300 seconds; PostgreSQL still decides when a job or financial source is due.
SIGTERM and cancellation propagate to the worker's owned-claim cleanup.
Startup failures stop the process with a sanitized error instead of spinning.
This does not add a public listener or enable any deployment. Private HTTP
authority, public proxy integration and secret/TLS delivery remain separate
runtime prerequisites.

The private ASGI application is `user_service.closure_authority:app`. It starts
only with `ACCOUNT_CLOSURE_AUTHORITY_ENABLED=true` and enforcement enabled,
checks the dedicated worker database role and native producer installation, and
uses the worker Keycloak client for exact-target intake preflight. It serves only
closure commands and authenticated lifecycle reads; it starts no event consumer,
public user API, metrics endpoint or API documentation. Supervise the polling
command separately. Both private processes require the private configuration.

The public app forwards its existing closure paths to
`ACCOUNT_CLOSURE_AUTHORITY_URL` over HTTPS (HTTP is limited to development/test).
It forwards the original native bearer token for commands; the private app
independently validates the user/operator and takes the actor from those claims.
Reader calls forward only the read credential and tenant header. Redirects,
unbounded/invalid responses and unavailable authority fail closed. Private apps
use their own session maker without replacing the public process's maker.
The public app rejects the private worker DSN and Keycloak writer secret at
startup. Existing read-only Keycloak preflight credentials are no longer needed
in the public forwarding process.

This source change does not provision database roles, deliver secrets or TLS,
configure a listener, deploy the private services or enable closure. Database
least-privilege grants, private network/listener configuration and end-to-end
acceptance remain required before activation. The ordinary public database role
must not inherit the private worker's global authority.

When enforcement is enabled, public startup also checks the effective database
role and every role it can select with `SET ROLE`. Superuser, RLS bypass,
role/database creation and replication authority are rejected, along with table
or column write privileges on lifecycle, retirement, source-binding, producer,
transition and anonymous-accounting state. Private worker entrypoints and
installed native security-definer functions must not be executable by these
roles. Raw lifecycle, source-binding, producer and transition inventories also cannot
be readable by the public role, including through column grants. Retirement
marker SELECT remains required for enrollment admission; anonymous accounting
reads remain permitted.
Enforcement stays off until the public role satisfies these checks and
`ACCOUNT_CLOSURE_AUTHORITY_URL` is configured.

To prepare a new dedicated private role for DBA review, run:

```sh
python core/user-service/scripts/prepare_closure_database_role.py \
  --role spanopticon_account_closure --database spanopticon > closure-role.sql
```

This command prints a transaction and never connects or applies it. The plan
creates a fresh NOLOGIN role, grants database connection and the specific local
profile/lifecycle permissions and private owner functions required by the worker,
and grants no direct billing/payment/Hypermesh source DML or schema creation.
The role deliberately has BYPASSRLS for the worker's global profile/lifecycle
inventory. It must remain private. Existing-role reuse fails; grants are not
silently layered onto an unknown principal. Review and apply through the normal
DBA path, then provision login credentials through the private secret mechanism.
No password, login activation, production grant or feature activation occurs in
this change. Public application CRUD grants remain owned by its deployment.

## Private TLS runtime preparation

`compose.account-closure.yaml` is an explicit opt-in overlay with an
`account-closure` profile. It is not included by the default VM wrapper. It
prepares separate authority and polling containers using the same reviewed
`ghcr.io/hyperme-sh/user-service@sha256:...` image. The runtime entrypoint rejects
a tag or a missing digest. Both containers run as UID/GID 65532 with a read-only
filesystem, no capabilities, no privilege escalation and bounded memory/PIDs.
They publish no host port. The authority waits for healthy PostgreSQL and
successful migrations; the worker waits for authenticated TLS readiness, which
rechecks the private database role and native installation. Readiness is not
financial or provider acceptance.

Prepare these operator-owned inputs before including the overlay:

- `ACCOUNT_CLOSURE_IMAGE`: the reviewed user-service image digest.
- `ACCOUNT_CLOSURE_PRIVATE_ENV_FILE`: a restricted file based on
  `examples/account-closure.private.env.example`, containing only private
  authority/worker configuration. The worker DSN must use the reviewed role;
  configure the exact native Keycloak issuer, JWKS, worker client and distinct
  guard/operations credentials. Operator clients require their explicit list.
- `ACCOUNT_CLOSURE_PUBLIC_ENV_FILE`: a separate reader file based on
  `examples/account-closure.public.env.example`. It contains no writer secret
  or private DSN. Existing public application configuration stays separate.
- `USER_SERVICE_DATABASE_URL`: the ordinary public role, satisfying its startup
  checks. The private DSN must not replace it.
- `ACCOUNT_CLOSURE_AUTHORITY_HOST`: a certificate DNS name, used as a private
  Docker network alias. Its certificate must cover that exact name. Use a CA
  already trusted by every native guard/owner client when configuring their
  HTTPS destinations; the proxy's custom CA setting does not change other
  services' certificate trust. Configure their guard URLs and enforcement
  through their existing deployment configuration before activation.
- `ACCOUNT_CLOSURE_TLS_CERT_SOURCE`, `ACCOUNT_CLOSURE_TLS_KEY_SOURCE` and
  `ACCOUNT_CLOSURE_TLS_CA_SOURCE`: certificate chain, matching private key and
  trusted CA bundle. Install the key as a regular file readable by UID 65532,
  with owner-only permissions (0400 or 0600). Startup rejects links, unreadable,
  oversized, mismatched or malformed files and never prompts for a passphrase.

The authority listens on TLS port 8443 inside the project network, without
access logs, forwarded-header trust, WebSockets or a metrics listener. Its
readiness route is reader-authenticated and has no public forwarding route.
The public proxy and readiness probe use an explicit SSL context for the CA
bundle, with certificate and hostname verification enabled; they do not rely
on `SSL_CERT_FILE` with HTTPX environment trust disabled. Native owner/guard
HTTPS delivery and Keycloak protection/client-role setup remain prerequisites.

Validate the composed VM configuration without printing resolved secrets:

```sh
docker compose -f docker-compose.yaml -f docker-compose.vm.yaml \
  -f compose.account-closure.yaml --profile account-closure config --quiet
```

All example activation flags are false. This change prepares source wiring and
local qualification only; it does not create certificates, supply credentials,
apply the role plan, start production containers, enable closure or establish
live provider/physical acceptance. Monetary-source cleanup and full #369
acceptance remain unfinished.

Private account checks honor the canonical retirement marker even when a legacy
account has no lifecycle root. Absence of that root cannot reopen authentication.
Resubmission still requires explicit reconciliation and never mints a new empty
inventory for an already-retired identity.
