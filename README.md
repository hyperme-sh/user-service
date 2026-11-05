# user-service

## Current version authority

Current development version: `0.1.0`. The services remain before the unreleased
0.24.0 milestone. Earlier 0.24/1.0 preparation and publication notes below are
historical and do not authorize those versions. Existing tags and historical
artifacts remain untouched. Development uses exact source pins and rebuilt
artifacts; no prior release is required. Version changes, tags and publication
require the owner's explicit authorization to the agent.

User and operator-account service implementation under `core/user-service`.
The separately installable read-only operator ban contract is under
`core/user-service/contracts`. Its public module is `operator_ban_store`, version
0.1.0. It returns boolean predicates while preserving caller transactions and RLS.

## Contract development

Use Python 3.13 and uv 0.11.26. The runtime needs SQLAlchemy only. PostgreSQL
integration tests use an immutable private controlplane-db revision as a dev
dependency; provide existing HTTPS read access to that repository.

```sh
cd core/user-service/contracts
TEST_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:PORT/postgres bash scripts/check-package.sh
```

Use only a disposable PostgreSQL server with database/role creation permission.
Tests create a unique database, apply platform migrations, validate explicit
scope and RLS, then drop that database. Checks run from source, an external wheel
and a rebuilt sdist; wheel bytes must match source. No deployed database is used.

The enabled shared-runner main-only workflow validates this contract with scoped
read access to hyperme-sh/controlplane-db, pinned actions, a disposable PostgreSQL
service and read-only contents.

## Standalone service development

`core/user-service` builds `user-service`; `core/user-service/contracts` remains
an independently packaged operator-ban contract. Runtime dependencies use exact
private Git revisions in its standard metadata and `uv.lock`. The service wheel
installs `user_service` directly, without workspace paths or `PYTHONPATH`.

Use Python 3.13+, uv 0.11.26, Docker and existing read access to the listed private
repositories. The full source/wheel/rebuilt-sdist suite starts disposable
PostgreSQL and Keycloak containers. Missing native prerequisites fail validation.

```sh
bash scripts/check-package.sh
```

For container qualification, provide `DEPENDENCY_READ_TOKEN_FILE` as a protected,
short-lived read-only GitHub credential file and `TEST_DATABASE_URL` pointing to
an owned disposable PostgreSQL server with database creation privileges:

```sh
bash scripts/check-container.sh
```

The build uses a BuildKit secret, installs the frozen production graph, and
runs as uid 65532. Container checks create and remove a unique migrated database,
then exercise real health/version/authentication HTTP behavior. The same image
also starts the private authority with a generated short-lived TLS certificate
and a unique database role produced by the owner's least-privilege role plan.
Authenticated readiness, reader/writer separation, committed retirement reads,
incomplete-inventory denial and untrusted-certificate rejection are exercised
over HTTPS. Only explicit fixture configuration enters that container. This
does not qualify a deployed issuer, owner mutation, scheduler or registry manifest;
the image reference uses the local image digest for this owned fixture only.
The checks do not apply migrations at application startup or deploy a service.
Publication requires successful full-service and contract qualification.

The standalone workflow uses the existing main-only shared-runner lane and
requires read access to all pinned private runtime/test repositories. It does
not add an approval gate, publish a service image, or enable closure. The
external source Compose checks live in `integration/source-runtime`; separated
plane delivery and shared/Hypermesh consumer adoption remain distinct gates.

## Release channels

Main validation retains its exact qualified files in Actions artifacts. It does
not create GitHub releases or tags. Historical `test-<commit>` prereleases remain
qualification evidence and do not establish an accepted stable release.

Stable publication requires an explicit `vMAJOR.MINOR.PATCH` tag, the exact
successful main validation artifact, compatible declared contracts and an actual
immutable stable baseline. The publisher independently verifies that evidence;
successful caller jobs alone cannot establish acceptance. Missing evidence and
first-stable bootstrap remain closed. Package qualification, coordinated consumer
acceptance and runtime deployment remain separate.

## Private closure adoption

The private closure implementation and source #720 retirement guard are
in `core/user-service`. See [the adoption gates](docs/closure-adoption.md).
The follow-up adopts owner dependencies and standalone service validation.
See the adoption document for exact revisions, validation results, and remaining
consumer/deployment gates. All closure flags remain default-off.

### Published owner artifacts

Test-channel publication follows successful `Standalone service` main validation.
That job validates the full service and operator-ban library in source, wheel and
rebuilt-sdist contexts, then qualifies the standalone container before retaining
the exact tested wheels and source archives together. The publisher downloads
those bytes without rebuilding. A contract-only run cannot publish a new owner
release. Existing immutable releases retain their original scope and provenance.

This artifact inventory does not establish deployed readiness or coordinated
release acceptance; version alignment, accepted baselines and downstream consumer
qualification are tracked separately.

The `user_service-VERSION.owner.zip` archive contains exactly the full-service
and operator-ban wheels at the same version. `scripts/owner_artifact.py` verifies
both wheel identities and complete runtime inventories without importing code.
The archive digest binds both distributions; its exported runtime contract does
not yet establish installer/dependency metadata compatibility.

Both owning distributions use 0.1.0. The contract consumes database 0.1.0
for its PostgreSQL checks; the full service retains its existing qualified
private dependency closure while downstream core/auth coordination proceeds.
This staged package alignment is not complete fleet dependency qualification.

### Prepared owner artifacts

The preparation branch retains the current private dependency pins and prepares
both owning packages as 0.1.0. Exact clean Git checkouts supply the dependency
fixtures; their manifest records source revisions and wheel digests. These are
locally built fixtures qualified by PR consumers, not published 0.24 baselines.
The older synchronized foundation artifacts lack account-closure interfaces used
by this service, so adopting them would regress its current functionality.
Dependency alignment must first preserve those interfaces in the foundation owners
(see [dependency qualification](https://github.com/hyperme-sh/user-service/issues/32)).

`bash scripts/check-package.sh --fixtures` runs source, installed-wheel and
rebuilt-sdist native consumers without private Git credentials. The complete
active graph is verified against root metadata, lock entries and transitive wheel
metadata. Optional private extras are not selected by this service; the verifier
rejects explicit extras rather than silently dropping them. The PR lane retains
qualified owner artifacts only. Non-root image qualification and deployed/provider
acceptance remain separate. Keep preparation PRs ready and unmerged where merging
would trigger publication.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
lives under `releases/qualification`; the current wheel binding is still checked
by package CI, alongside any future explicit stable candidate. Earlier test
snapshot receipts are preserved there with an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests; a test snapshot cannot
become accepted through a provenance label. No stable baseline is recorded until
that release exists. Stable publication remains closed without a valid baseline;
first stable bootstrap and coordinated release qualification remain separate.
No stable version, approval prerequisite or deployment is introduced here.

### Actions qualification and stable publication

Main merges and workflow completion do not publish GitHub test releases. Exact
qualification files remain in Actions artifacts with finite retention. The pinned
publisher independently verifies a real immutable stable baseline and refuses
qualification snapshots, even if a caller job reports success. Existing valid
stable records are retained; no release, version change, deployment or human
approval prerequisite is introduced by this correction.


### Initial stable declaration

When there is no accepted stable release, the pinned admission workflow checks
this repository's complete live release inventory and the exact owning package
versions against `releases/candidate`. A stable release or incomplete inventory
rejects this path. Candidate metadata identifies built artifacts; it does not
establish an accepted baseline or publish anything. The exact-pinned publisher
independently validates tested bytes and serializes any later explicit first
stable publication. Test snapshots remain qualification evidence only.

## Contract database qualification

The operator-ban contract test dependency follows the same closure-capable DB
revision as the service graph recorded in `docs/closure-owner-graph.json`.
Exact-source test fixtures are consumer evidence, not stable release acceptance.

## Verification erasure owner

When verification is enabled, configure `ACCOUNT_CLOSURE_VERIFICATION_ENABLED=true`, `ACCOUNT_CLOSURE_VERIFICATION_URL` and
`ACCOUNT_CLOSURE_VERIFICATION_TOKEN` (the owner's dedicated admin credential).
Personal erasure calls the private owner endpoint after the existing closure and
retention checks; it records only a completed receipt and retries unavailable
owners. Missing configuration means that owner has not been enabled and must
block verification rollout acceptance. Verification also uses the existing
read-only lifecycle check on each request and before delivery.

## User mutation authority

User creation and deletion require a current, active tenant administrator bound
to the authenticated identity-provider subject. A cached administrator token
claim cannot replace a removed role, disabled account, or inactive tenant. The
existing portal invitation controls continue to apply.

Profile updates require the same current administrator authority or an active
subject binding to the target user's own account. Email claims and local user
IDs alone do not establish self. Ordinary users may update their own first and
last names. Replacing any SociACL document requires current administrator
authority, including self updates: the document contains verification assurance
and internal policy notes, and partial replacements could erase those fields.
All mutations retain token/header tenant matching and tenant-scoped targets.

The native HTTP regression suite covers stale tokens, account and tenant
deactivation, removed bindings, same-tenant horizontal writes, cross-tenant
targets, legitimate self edits, and current administrators. Source adoption and
deployed runtime adoption are separate; this change does not deploy the service.

## Operator console reads

Database-backed directory pages read active user bans from tenant-scoped durable
records for that page. Process-local entries cannot hide a committed ban or
restore a lifted one. Group/device bans do not become user bans.

`GET /api/v1/operator/audit` reads durable tenant history whenever a session is
available. It preserves the existing public row fields and requires both console
and support authority. Results are newest first, ordered by creation timestamp
then UUID descending, with `limit` defaulting to 50 (maximum 200) and `offset`
defaulting to zero. Transient local diagnostics are not merged into durable
history. Reads never commit the caller's transaction or promote local-only rows
to the database.

Without a session, isolated test applications retain tenant-scoped, paginated
in-memory audit history and empty directory responses. Database errors do not
switch a session-backed read to local state. Native tests exercise committed
ban/lift/role history across independent sessions, rollback visibility,
timestamp ties, tenant isolation and HTTP authorization/pagination boundaries.

## Durable-ban transfer and licensing

The two remaining durable-ban regressions from Panopticon
`2cd00fd9a7ebb950999571a81be7cb0a24d9264e` now run in the owning service's
source, wheel and rebuilt-sdist suites. They verify one committed winner for
concurrent lifts and persistent directory/soft-delete ban status after clearing
local process state. Soft-delete reads the stored ban when a database session is
available. No ban is created or lifted by soft-delete.

The three service test inventories must match with no skipped cases. Local
qualification can retain JUnit files through `TEST_EVIDENCE_DIR`.

First-party service and operator-ban contract code are [Apache-2.0](LICENSE).
Both distributions include checked SPDX metadata and exact license text.
Bundled dependencies retain their own licenses; versions remain unchanged.

## Coordinated test bundles

This service opts into the `next: 0.24.0` train through
[.github/test-channel.json](.github/test-channel.json). Successful main validation
publishes its exact retained `tested-dist` files as immutable `0.24.0-test.N`
prerelease bundles. The pinned publisher verifies the run, source revision,
configuration and original Actions artifact digest without executing caller code
or receiving private dependency credentials. PRs validate without publication.

This test-channel authorization supersedes the older main-publication restriction
above. Package versions, dependency pins and accepted package baselines stay
unchanged; existing stable package admission remains separate. Coordinated
consumer/deployment selection must bind exact component commits and artifact
digests, not matching repository-local counters. No stable promotion is automatic.
Private jobs use debrunners and public jobs use hosted Ubuntu; no approval gates
are introduced. Missing original evidence or publication collisions fail closed.

## Redeemable operator password resets

`POST /api/v1/operator/mail/password-reset` requests the bound identity
provider's password-action email. It requires console and support authority,
the current tenant's active user record, a bound subject, and the matching
email confirmation. It no longer invents a reset token or reports success from
the Mailgun preparation stub. Successful response fields remain `sent`, `kind`,
`user_id` and `detail`; no token, password or action URL is returned or audited.

The public process holds only a reset-request capability. A separate private
`user_service.password_reset_authority:create_app` process holds the dedicated
IdP credential. The private authority verifies both the purpose token and the
original operator bearer/tenant, independently rechecks the active tenant/user
through a read-only RLS-scoped database connection, and verifies the exact
subject/current email with Keycloak. Only `UPDATE_PASSWORD` with a 600-second
lifespan can be requested; callers cannot choose actions, recipients or
redirects. Existing local password accounts are supported. Brokered/external
identities, passwordless identities and reserved service-account identities are
refused rather than acquiring a new login method.

Keycloak creates and delivers the expiring action through its configured SMTP
service and owns redemption and single-use state. The API acknowledges success
only after the provider's send acknowledgment. Timeouts are reported as
unconfirmed; mail may already have reached the provider, so delivery is not
claimed to be exactly once. The existing process-local monthly mail cap reserves
a slot before awaiting the authority, releases failed attempts, and audits only
acknowledged sends.

Configure the public process with:

| Setting | Purpose |
| --- | --- |
| `PASSWORD_RESET_AUTHORITY_URL` | Private HTTPS authority origin |
| `PASSWORD_RESET_OPERATIONS_TOKEN` | Dedicated random capability, 32–512 ASCII characters |
| `PASSWORD_RESET_AUTHORITY_CA` | Optional private CA file; normal certificate verification otherwise |

Configure the private process separately with that capability, the existing
operator tenant-session verifier configuration, and:

| Setting | Purpose |
| --- | --- |
| `PASSWORD_RESET_DATABASE_URL` | Dedicated `postgresql+asyncpg` login with SELECT on `public.users` and `public.tenants` |
| `PASSWORD_RESET_DATABASE_CA` | Required trusted database CA outside loopback development/tests |
| `PASSWORD_RESET_KEYCLOAK_URL` | Issuer's HTTPS server base |
| `PASSWORD_RESET_KEYCLOAK_REALM` | Realm matching the configured `keycloak_issuer` |
| `PASSWORD_RESET_KEYCLOAK_CLIENT_ID` | Exactly `operator-password-reset` |
| `PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET` | Dedicated realm client credential; never a closure or actor-signing credential |
| `PASSWORD_RESET_KEYCLOAK_CA` | Optional issuer CA file; normal certificate verification otherwise |

The private process refuses writable users/tenants privileges, column grants,
superuser/BYPASSRLS and other privileged settable roles. Each request runs a
read-only transaction with the operator's tenant GUC. It has no public routes,
OpenAPI or unrelated authority endpoints. Run it on a private HTTPS listener
with a valid certificate; do not mount its database or IdP credentials into the
public service, whose startup rejects them. The purpose capability, actor
signing key and IdP credential must be distinct. Environment proxy inheritance
and redirects are disabled; plaintext is allowed only for loopback development
or disposable tests. Missing configuration fails closed.

Native tests use a disposable Keycloak instance with a verified TLS certificate
and a local SMTP receiver. They exercise actual email delivery, password change,
expiry, fresh-browser replay refusal, an unaffected second user, unsupported
identity types, SMTP/TLS failures and a private authority with a restricted
PostgreSQL role. Source/wheel/sdist consumers retain the mandatory native tests
and no-skips assertion. Deployed configuration and delivery qualification remain
tracked separately in issue #41; this implementation does not provision roles,
credentials, SMTP, listeners or deployments in an existing environment.
