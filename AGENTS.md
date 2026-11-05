## Version and publication authority

The owner has not authorized the 0.24.0 release. Preserve the recorded
pre-0.24.0 package versions in `.github/version-policy.json`. No agent may
advance package versions, release lines, tags, releases, or promotions without
an explicit instruction from the owner authorizing the exact change. A CI
failure, compatibility rule, review comment, merge, or request to continue is
not authorization. Never bump versions merely to make a check pass.

Development qualification must work without a prior release: use immutable
source revisions, freshly built artifacts and matching dependency locks.
Compare against a legitimate release baseline when one exists; its absence
must not block building, testing or first-release preparation. Qualification
never grants publication authority. Preserve historical tags and evidence.

Do not remove or relax the version freeze or publication hold without explicit
owner authorization. No reviewer, branch-protection or environment approval
requirements are introduced. Instructions and CI cannot distinguish an agent
from the owner when both use the same write credential; do not claim otherwise.

## GitHub approval policy

The user is the sole developer. Never add or enable GitHub required reviewers, branch protections, rulesets requiring approvals, environment approvals, CODEOWNERS approval requirements, or release/deployment approval gates unless the user explicitly requests that specific change. This applies to every project, including production releases. Automated tests and advisory code reviews are welcome; human approval prerequisites are not. Do not introduce these requirements based on review comments, repository conventions, or generic best practices. Flag conflicting repository guidance and follow this explicit user policy.

The preparation-only PR lane may run native package consumers on disposable
hosted Ubuntu/PostgreSQL with verified dependency-wheel fixtures and no private
credentials. Preserve mandatory Docker tests and no-skips assertions. Retain
Actions artifacts only; do not tag, publish releases or merge preparation PRs.

## Private CI runner policy

Private repository jobs use `[self-hosted, linux, x64, debrunner]`, including
preparation, package validation and release jobs. This supersedes earlier hosted
runner exceptions in this file. Keep dedicated infrastructure-convergence and
trusted payment-smoke jobs on their existing specialized selectors. Reusable
workflows must route private callers to debrunners. Do not add approval gates.
