## GitHub approval policy

The user is the sole developer. Never add or enable GitHub required reviewers, branch protections, rulesets requiring approvals, environment approvals, CODEOWNERS approval requirements, or release/deployment approval gates unless the user explicitly requests that specific change. This applies to every project, including production releases. Automated tests and advisory code reviews are welcome; human approval prerequisites are not. Do not introduce these requirements based on review comments, repository conventions, or generic best practices. Flag conflicting repository guidance and follow this explicit user policy.

## Private CI runner policy

Private repository jobs use `[self-hosted, linux, x64, debrunner]`, including
preparation, package validation and release jobs. This supersedes earlier hosted
runner exceptions in this file. Keep dedicated infrastructure-convergence and
trusted payment-smoke jobs on their existing specialized selectors. Reusable
workflows must route private callers to debrunners. Do not add approval gates.
