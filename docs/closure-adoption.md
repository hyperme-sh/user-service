# Private closure source adoption (draft)

This source port prepares the user-service implementation needed for source PR
#720, including its private authority, native lifecycle reader, worker and
prerequisite user-owned closure implementation. It does not complete component
integration and must not merge or activate before the dependency gates below.

## Provenance

- Reviewed source: `FyberLabs/panopticon` commit
  `7356887667b0f142bac7504223ebf9446e0f5411` (PR #720, still open at adoption).
  Its retirement-only guard consults the canonical retirement marker without
  minting an empty lifecycle root. The source's nine targeted tests, 337 user
  tests, all six CI groups and current-head reviews passed.
- It includes merged source PRs #705/#707/#710/#712/#714/#717 and #721's bounded
  real-Keycloak startup fixture correction. The PR numbers in this section refer
  to that external source repository, not this repository.
- Component base: `2007610a7548879da0fc767f4267fbfcb9914fff`.
- Component changes preserve `spanopticon_models`, the `spanopticon_auth`
  discriminator and existing durable operator-ban fixes. No old namespace is
  accepted as a compatibility authentication credential.

## Merge blockers and owner handoffs

The component currently has no standalone service lock or resolved dependency
closure. Existing operator-contract pins validate only that contract. This draft
keeps that contract and its exact pins unchanged; it does not invent service pins
or treat workspace placeholders as installable dependencies.

| Owner | Required adoption before integration |
| --- | --- |
| controlplane-identity | `account_lifecycle` guards, authenticated owner-call helpers, exact protected-target authority and native JWT compatibility |
| controlplane-tenancy | `lock_identity`, `retire_identity`, `identity_retired_at`, retirement admission fences and tenant membership authority |
| controlplane-db | Identity retirement model and platform closure migrations, worker preflight, financial epochs/GC primitives and native owner proofs |
| controlplane-core | Profile erasure/inventory, personal/company ownership, payer-risk hooks and context/session APIs consumed by closure |
| auth-service | Durable retirement admission, current subject/credential projection and exact closure-token boundaries |
| payment-service / hypermesh-plane | Native owner inventory, proof/permit checks, financial clocks/fences and default-off private owner endpoints |
| spanopticon / controlplane-edge | Private TLS/runtime delivery, owner-specific migration graph and public forwarding; no public private-authority listener |

The platform migration histories have diverged: component main has its own
share-lookup hardening revision while source closure starts after a checkpoint
revision. Do not copy over the frozen registry, rewrite existing revisions or
advance migration heads by file presence. Review and test the graph with each
owner before selecting immutable dependency pins.

Standalone dependency closure, wheel layout, container/HTTP validation and
consumer adoption remain tracked in #3/#5. These must pass with the selected
reviewed owner commits before this draft is ready to merge. Issue #14 remains
open. No source PR is reported merged merely because its files are imported.

## Validation boundaries

`scripts/check-closure-owner-harness.py --owner-root /path/to/source-checkout`
archives the exact reviewed owner commit into a disposable directory, overlays
this component's service code/tests, and runs its owning PostgreSQL/HTTP/Keycloak
suite using the owner's existing test Python. It adapts matching source module
paths, issuer/tenant-claim identifiers, auth discriminator and configuration prefix for the component namespace;
frozen migration and registry bytes remain unchanged. It does not test the
currently extracted dependency packages, qualify issuer/claim cutover, or supply
standalone dependency pins. The complete namespace cutover remains coordinated.

The source harness is external development evidence only. The contract's own
source/wheel/sdist checks remain separate and do not establish service readiness.
No Actions/runner policy, deployment configuration, production grants, secrets,
provider identities or enablement flags are changed. All closure flags stay
explicitly default-off. Production retention and test-environment policy require
their existing owner decisions; this port changes neither.

Historical source references and the explicit external harness adapter retain
legacy spellings only to identify their actual owner inputs. Coordinate their
reviewed line fingerprints with the organization naming registry when integrating
this draft; do not add an authentication fallback for the old namespace.
