# User publication preparation

The service and operator-ban contract retain version 0.1.0 and Apache-2.0.
Original and rebuilt wheels verify owner LICENSE and NOTICE bytes.

The existing runtime preserves indexed installed dependency legal texts.
CI verifies installed owner/legal bytes and scans every image layer before the
existing GHCR publisher advances moving TEST. No third-party source archives
are downloaded or bundled; no registry settings are changed.

Reachable history includes fetched branches, tags and archived wheel members,
without executing old code. Findings are a review queue, not publication
clearance. Deleted refs, remote LFS and external archives are outside scope.
The historical ledger binds 697 archived dependency findings to exact blob and
member hashes: 389 payment-schema entries and 308 hosted implementation/metadata
entries. They remain retained and uncleared for publication.

CI inventories tagged and untagged GHCR versions and inspects every retained
Linux amd64 layer without executing older images. Inventory failures fail the
review rather than count as absence. PRs run the review, and the main workflow
calls it again after publication so the new version is included. Image jobs run
in parallel with read-only package access. Deleted versions, other registries
and non-amd64 platforms remain outside this review. No old image is deleted,
republished or assigned a new visibility.
Integration/e2e remains nightly; existing CI checks continue unchanged.
