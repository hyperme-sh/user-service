# Private closure adoption

The source port in merged PR #16 prepares the user-service implementation needed for source PR
#720, including its private authority, native lifecycle reader, worker and
prerequisite user-owned closure implementation. Its source-harness evidence did not establish standalone installation. The
follow-up below addresses dependency and packaging gates; activation remains
separate.

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

## Historical source-port blockers and owner handoffs

At the PR #16 source-port gate, the component had no standalone service lock or
resolved dependency closure. Existing operator-contract pins validate only that contract. This draft
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
explicitly default-off. The approved TEST-mode retention/hold exemption remains tracked in #13 and
is an activation blocker for TEST until implemented. This port does not change
that requirement or the production retention policy.

Historical source references and the explicit external harness adapter retain
legacy spellings only to identify their actual owner inputs. Coordinate their
reviewed line fingerprints with the organization naming registry when integrating
this draft; do not add an authentication fallback for the old namespace.

Component source validation: 335 owning-service cases passed before the review
follow-ups, and both new regressions pass in focused checks. Full current results
are recorded in PR #16. The external owner harness exercises real PostgreSQL, private
HTTP/TLS and native Keycloak tests. This preserves destination durable-ban
coverage. The operator permission/retirement callback runs off the server event
loop, and service tests use their own disposable migrated database. These results
do not supply the missing standalone dependency pins or container acceptance.


Component review also bounded the whole owner RPC to five seconds, including
response streaming, rather than only individual HTTPX waits. A timed-out stream
closes and the client can process the next call. Retirement-only subjects now
prevent a denial snapshot from claiming completeness until their original
inventory is reconciled; no empty lifecycle root is manufactured. Both regression
cases failed before correction and pass afterward in the owner harness.

## Standalone dependency adoption follow-up

PR #16 merged at `51a3fd0913cf6b894ccffc277f41bc499d09e1d4` before this
follow-up. Historical blockers above describe that port, not completion of this
new gate. The existing service project now uses installable immutable dependencies rather
than workspace placeholders; the operator-contract project is unchanged.

| Dependency | Exact revision | Adoption PR |
| --- | --- | --- |
| controlplane-db | `a14a4a35b5dbb45b7b9050ad35fcc65b4ef8fc79` | [#11](https://github.com/hyperme-sh/controlplane-db/pull/11) |
| controlplane-identity | `fbdeb1c11f17fa192b7505355c64d1f0af1234dc` | [#9](https://github.com/hyperme-sh/controlplane-identity/pull/9) |
| controlplane-tenancy | `9528e2e58463c44fd0affa58089d6fb1215da605` | [#11](https://github.com/hyperme-sh/controlplane-tenancy/pull/11) |
| controlplane-api | `6bef00ce7fc630df5523dcd254f85d40d13d135e` | [#12](https://github.com/hyperme-sh/controlplane-api/pull/12) |
| controlplane-core | `3aa01d738c3a20d0da37506a2b44d186a8496500` | [#12](https://github.com/hyperme-sh/controlplane-core/pull/12) |
| auth-service | `4766edb227942d8a481a9b5b4d3c1af9f079fb58` | [#16](https://github.com/hyperme-sh/auth-service/pull/16) |

The database owner preserves both existing platform histories and joins them at
`platform_0079_closure_merge`. Neither the source checkpoint/closure branch nor
the destination share-lookup hardening revision was rewritten. Fresh installs
and upgrades from both previous platform heads pass all native migration tests;
existing frozen baselines and previously common revision bytes remain intact.
Payment and Hypermesh producer chains use the same adopted database resource
package, without importing a product checkout or changing producer deployment.

The identity async review fixes preserve offline context across worker threads
and provide explicit async tenant/host-setup session decoders. Auth bridges its
async consumers and applies retirement checks to introspection. Tenancy uses a
consistent SQL email normalization for credential ownership, ambiguity detection
and deletion, including Unicode whitespace. These changes retain caller-owned
transactions and explicit tenant scopes.

Standalone qualification runs the full 344-case native suite from Python 3.13
source, an external installed wheel, and a rebuilt sdist. Container checks use
the frozen production graph and a unique migrated disposable database. Final
results are recorded in PR #20 and the documentation roadmap; every native case
must pass without skips before readiness is claimed. Local source-harness
results above do not count as installed-component qualification. Existing CI runs on the main-only lane;
local results are separate from hosted CI. No GitHub approval requirements,
release channels, live grants, provider identities or deployment flags change.

Issue #5 can close after external wheel/import validation passes. Issue #3
remains open for shared/Hypermesh consumer integration, and #14 remains open
for coordinated private runtime acceptance. TEST policy #13 remains a separate
activation blocker. None of these gates is closed by file presence alone.

Standalone checks exposed one additional source prerequisite: core subscription
audits must use the persisted creator after the database retirement fence, not
the original request field. Core #12 includes that correction, with an owner
regression and the real user-service erasure/payment-consumer case.

Merge the owner adoption PRs in dependency order: database and identity, then
tenancy and API, core, auth, and this service follow-up. The existing release version-source paths and reusable policy pin are preserved. These are advisory
reviewed code changes; no human approval prerequisite is configured.

The standalone CI job retains the existing main-only runner boundary. A green
PR release-configuration check is configuration evidence; it is not a substitute
for the local native package checks or a claim that hosted standalone CI ran.

Security re-review showed that a general version-source move exception could
redirect admission to a decoy manifest. The service instead retains its
original metadata path and corrects the standalone wheel configuration there.
The proposed exception in Spanopticon #8 is withdrawn; no release-policy
relaxation is needed.

Merged database main subsequently adopted lab/enforcement resources. The
follow-up rebases onto that owner revision and preserves all 64 current-main
resources plus the 50 imported source resources byte-for-byte. A second no-DDL
merge, hypermesh_0087_closure_lab_merge, joins the lab and closure branches.
Database checks cover fresh installs, both earlier platform heads and both
earlier Hypermesh heads, including retained lab receipts, RLS and private worker
preflight. The refreshed owner graph is used consistently by tenancy/core/auth
and this service.

## Separated consumer and private runtime follow-up

The six owner PRs above and service #20 have merged. Service #20's merge commit
is `304c9f142c78ab9accfad4cb8115bd14286744f8`; consumer fixtures install that
immutable service distribution, without monorepo source-path injection.

- [Ticket #15](https://github.com/hyperme-sh/hypermesh-ticket/pull/15) aligns its
  identity pin while preserving signed ticket vectors.
- [Payment #21](https://github.com/hyperme-sh/payment-service/pull/21) adopts the
  same dependency graph and the frozen native financial-authority lookup helper.
  Native ownership remains authoritative after profile scrubbing; contact-only,
  UUID-collision and ambiguous mappings cannot become financial authority. This
  helper does not add deletion endpoints or change financial policy.
- [Edge #24](https://github.com/hyperme-sh/controlplane-edge/pull/24) exercises
  this installed service's forwarding router and preserves native bearer
  authority only on the exact self/operator closure methods. Private paths stay
  unavailable through the edge, including preflight. Failed retirement checks
  cannot fall through to development JWT decoding.
- The Hypermesh owner adopts the same graph without foreign workspace overrides,
  purpose-bound owner inventory/closure, exact physical model-cleanup receipts,
  and native PostgreSQL consumers of this service's committed bans and lifts.
  Running leases and newer lab/enforcement state remain preserved; gateway
  receiver adoption and provider acceptance remain separate.

The separated private runtime now requires the canonical
`ghcr.io/hyperme-sh/user-service@sha256:...` image namespace. Public and private
configuration examples under `core/user-service/examples` ship in the source
distribution with every activation flag false. Public configuration contains no
writer credential, private database URL or worker Keycloak secret.

`scripts/check-container.sh` now qualifies both installed applications. In an
owned disposable database it applies the owner's SQL role plan to a unique
private role, then starts the authority as uid 65532 with generated short-lived
TLS material. Real HTTPS checks verify authenticated readiness, reader/writer
separation, committed canonical retirement, incomplete-inventory refusal and
untrusted-certificate rejection. Ambient owner configuration is not forwarded.
Only the fixture enables enforcement/authority, and its issuer is an unreachable
local test address. This is not live Keycloak, owner mutation, worker/scheduler,
published registry-manifest or deployed acceptance. The local image config digest
is fixture input only.

Merge the reviewed ticket alignment before accepting the Hypermesh integration;
payment, edge and service changes remain default-off code adoption. Record final
component merges and main-only hosted validation separately from PR configuration
checks. Issue #13 remains a TEST activation blocker; overall source #369 and
deployment/cutover remain open. Source #720 is reviewed port provenance, not a
claimed source merge.
