# Releasing

`user-service` and `operator-ban-store` are version 0.1.0. [`release-policy.json`](../release-policy.json) records component line `0.1` and the two version files `core/user-service/pyproject.toml` and `core/user-service/contracts/pyproject.toml`. [`releases/candidate/release.json`](../releases/candidate/release.json) and [`releases/qualification/current/release.json`](../releases/qualification/current/release.json) use that same line and version. Qualification snapshots stay under `releases/qualification/` with `stable_release` false.

Admission for a stable tag is the checklist in [release compatibility](release-policy.md). The manifest format is the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).

## Test bundles

[`.github/test-channel.json`](../.github/test-channel.json) joins the coordinated channel `next: 0.24.0` and names `.github/workflows/service.yml` as the qualifying workflow. After `Standalone service` succeeds on `main`, `.github/workflows/test-bundles.yml` publishes the exact retained `tested-dist` files as an immutable `0.24.0-test.N` prerelease. The publisher checks the workflow run, the source revision, the channel configuration, and the original Actions artifact digest. It does not rebuild the packages or receive dependency credentials. Pull requests validate without publishing.

The bundle version is the test channel. The wheels inside it remain `user-service` 0.1.0 and `operator-ban-store` 0.1.0. A consumer selects a bundle by commit and artifact digest. Publishing a test bundle does not create a stable release.

## Qualification artifacts

`Standalone service` on `main` runs the service and the operator-ban library from source, from the installed wheel, and from a rebuilt sdist, then qualifies the container. The exact wheels and source archives from that run are retained as Actions artifacts. A contract-only run does not publish a service archive.

`scripts/owner_artifact.py` checks `user_service-VERSION.owner.zip`. The archive contains the `user-service` wheel and the `operator-ban-store` wheel at the same version. The script checks both wheel identities and their runtime inventories without importing the packages. The archive digest covers both distributions.

`bash scripts/check-package.sh --fixtures` runs those consumers from the verified wheels recorded under `core/user-service/tests_artifacts/dependencies`. The manifest stores the source revision and wheel digest for each fixture. Fixture wheels are test inputs. They are not a stable release.

Historical `test-<commit>` prereleases are development snapshots. The package version embedded in a snapshot does not reserve a stable version. Their receipts live under `releases/qualification/`, including an explicit non-stable classification for earlier snapshots. Merging to `main` keeps the qualification files as Actions artifacts. It does not by itself create a `v*` tag or a stable GitHub release.

## Stable publication

A stable release is an explicit `vMAJOR.MINOR.PATCH` tag plus the exact bytes from a successful main validation, a compatible contract, and an immutable baseline at `releases/accepted/release.json`. Set the repository variable `SPANOPTICON_RELEASE_BASELINE_SHA` to that baseline's full 40-character commit SHA. The publisher checks the live release, the tag's source commit, and the asset digests. A `test-<commit>` snapshot cannot become that baseline by a label in its provenance file.

When `releases/accepted` does not exist yet, admission compares this repository's live release inventory and the package versions with `releases/candidate`. Candidate metadata names the built artifacts. It does not publish them and it does not become the accepted baseline on its own. The first baseline needs the artifact and consumer evidence described in [release compatibility](release-policy.md). Invented digests are not that evidence.

These workflows do not deploy the service. Selecting a test bundle, accepting a stable baseline, and running the service in an environment are separate steps.
