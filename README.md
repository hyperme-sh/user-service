# user-service

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

The shared-runner main-only workflow validates this contract. Actions remains disabled
until DEPENDENCY_READ_TOKEN has contents:read on hyperme-sh/controlplane-db and
shared-runner qualification is configured. It uses pinned actions, a disposable PostgreSQL
service, read-only contents and a repository-specific Git authentication header.

## Service readiness

The service application, Dockerfile and service integration tests retain their
existing layout and dependencies. Full standalone service dependency closure,
container builds, owning-service/Hypermesh integration and consumer adoption are
not established by contract tests. Service deployment remains unqualified; package channels are described below.

## Release channels

Successful main-push validation retains the validated Python wheel and source distribution for the extracted contract only and publishes
an immutable `test-<commit>` GitHub prerelease. Push a `vMAJOR.MINOR.PATCH`
tag at that tested commit to promote the exact files to a stable release,
without rebuilding. Repository visibility applies to all package assets.
Package metadata versions are preserved; these are GitHub distribution snapshots,
not automatic PyPI publication or service deployment.

Promotion requires the original Actions artifact (90-day requested retention;
organization policy may shorten it). Expired evidence fails closed: validate a
new main revision. The publisher verifies the run, source, workflow and artifact
digest independently of release metadata. Repository immutable releases must be
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).
