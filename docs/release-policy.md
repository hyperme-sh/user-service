# Release compatibility

This component targets the shared **0.24.x** release line. Components share major
and minor versions; patch numbers advance independently and must preserve their
accepted API contracts. Existing package versions are retained until a qualified
release is prepared; installing this workflow does not qualify those versions.

`release-policy.json` identifies this repository and every package version file.
The pinned Spanopticon workflow checks this configuration on pull requests.
Version changes or a `releases/candidate/release.json` submission also require
release admission. Every tag push and manual release request requires admission.
A configuration-only result is not a release compatibility result.

Before attempting a release:

1. Produce a real accepted bundle at `releases/accepted/release.json`, with its
   contract files and immutable artifact references. Set the repository variable
   `SPANOPTICON_RELEASE_BASELINE_SHA` to its full 40-character commit SHA. The first
   baseline needs automated artifact/consumer qualification and provenance;
   examples and invented digests are not accepted release evidence.
2. Generate the candidate bundle at `releases/candidate/release.json` from the
   release artifacts. It must contain exactly this component, use line `0.24`,
   and match every declared owning package version and the requested tag/version.
3. Run admission against the trusted baseline. Patch contracts must remain
   unchanged; changing a published artifact at the same version is rejected.
   Verify artifact provenance and downstream consumer behavior separately.
4. Make successful admission and artifact/consumer validation automated
   prerequisites of the publisher for the exact release. Select the accepted
   baseline independently of candidate data and retain the validation evidence.
   This check validates the release artifacts in the pipeline.

Missing baselines stop publication. This workflow does not publish or deploy.
It does not enable repository Actions, grant private dependency access, or prove
that a declared artifact exists. See the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md)
for the manifest format and compatibility rules.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
lives under `releases/qualification`; the current wheel binding is still checked
by package CI, alongside any future explicit stable candidate. Earlier test
snapshot receipts are preserved there with an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests. A test snapshot stays
qualification evidence. No stable baseline is recorded until that release exists.
Stable publication waits for a valid baseline. First stable publication and
coordinated release qualification are separate from this document.

### Actions qualification and stable publication

Main merges and workflow completion do not publish GitHub test releases. Exact
qualification files remain in Actions artifacts with finite retention. The pinned
publisher independently verifies a real immutable stable baseline and refuses
qualification snapshots, even if a caller job reports success. Existing valid
stable records are retained.
