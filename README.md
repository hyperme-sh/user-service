# user-service

User and operator-account service implementation under `core/user-service`.
The separately installable read-only operator ban contract is under
`core/user-service/contracts`. Its public module is `operator_ban_store`, version
0.24.0. It returns boolean predicates while preserving caller transactions and RLS.

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
then exercise real health/version/authentication HTTP behavior. They do not
apply migrations at application startup or deploy a service. Publication requires successful full-service and contract qualification.

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

Both owning distributions now use 0.24.0. The contract consumes database 0.24
for its PostgreSQL checks; the full service retains its existing qualified
private dependency closure while downstream core/auth coordination proceeds.
This staged package alignment is not complete fleet dependency qualification.

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
