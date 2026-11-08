# User service

User service is the Hypermesh control-plane HTTP API for tenant users, groups, organizations, and operator accounts. The installable service is `user-service` 0.1.0 under `core/user-service`. It also publishes `operator-ban-store` 0.1.0, a read-only ban contract other control-plane processes call inside their own database transaction.

## Why

Hosts and renters are people in a tenant, and those people have to stay consistent across the portal, Hypermesh leases, and operator support. A ban, a closed account, or a removed administrator that exists only in one process will be wrong on the next request. This service is the directory and the operator console for that directory: who belongs to the tenant, which groups and organizations they are in, and whether support has banned or closed the account. Hypermesh keeps leases, devices, and host certification; it asks this service who the person is and whether that person may still act.

## How it works

The public process is a FastAPI application, `user_service.app:app`, started with `python -m user_service.main`. It listens on `HOST` and `PORT` (defaults `0.0.0.0` and `8000`). Each request opens one PostgreSQL session and sets `app.current_tenant_id` from `X-Tenant-ID` so row-level security applies. Authenticated routes also require a Keycloak access token whose tenant claim equals that header.

The public API is mounted at `/api/v1`:

| Area | Routes | Who calls them |
| --- | --- | --- |
| Directory | `/users`, `/groups`, `/organizations`, membership and role assignment | Portal and tenant administrators |
| Portal gates | `GET /me/portal-controls` | Portal, including `can_checkout`, `can_see_leases`, and `can_see_host_status` |
| Operator console | `/operator/bans`, `/operator/directory/users`, `/operator/audit`, password reset, soft-delete | Operators with console and support authority |
| Account closure requests | `/me/account-closure-request`, `/operator/account-closure-requests` | The signed-in person or an operator |
| Lifecycle reader | `/internal/account-lifecycle/check`, `/permit`, `/scope`, `/grant-scope`, `/financial-scope`, `/denials` | Control-plane guards, with `X-Account-Lifecycle-Token` |

Creating a user publishes `user.created.v1`. Adding or removing a group member publishes `group.member.added.v1` or `group.member.removed.v1`. The process also consumes `payment.succeeded.v1` on the Postgres event table (or Azure Service Bus when `AZURE_SERVICE_BUS_CONNECTION_STRING` is set), in consumer group `user-service-controlplane-events`. A succeeded Stripe invoice can attach the tenant's paid plan. A USDC payment does not: those payments settle Hypermesh leases and marketplace listings.

Operator bans are rows in `operator_bans`, scoped to the tenant. `operator-ban-store` exposes only booleans: async `active_ban` for users, groups, and devices, and `subject_banned_sync` for one subject on a connection the caller already holds. The package does not commit, change roles, migrate, or write bans. Database errors propagate so the caller can reject the request.

Account closure, password reset, and the lifecycle reader split into a public process and private processes. The public app forwards closure commands to `ACCOUNT_CLOSURE_AUTHORITY_URL` and refuses to start if a worker database URL or a Keycloak writer secret is present in its environment. The private worker and the private ASGI apps hold those credentials. Enforcement stays off until `ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED=true` and the public database role passes its startup privilege checks.

`GET /api/v1/health/` returns `{"status":"Ok"}`. `GET /version` reports the service name, git SHA, and build time baked into an image. The process does not apply schema migrations on startup.

## Practical use

Runtime dependencies are public packages pinned to exact commits in `core/user-service/pyproject.toml` and `uv.lock`: `controlplane-api`, `auth-service`, `controlplane-core`, `controlplane-db`, `controlplane-identity`, `controlplane-tenancy`, `controlplane-events`, and `spanopticon-models`, plus FastAPI `>=0.135.0`, HTTPX `>=0.28.1`, Pydantic `>=2.12.0`, PyJWT `>=2.10.1`, SQLAlchemy `>=2.0.43`, Uvicorn `>=0.37.0`, and Starlette `>=0.48.0`. Install Python 3.13 or newer and uv 0.11.26.

Apply the `platform` and `events` migration chains from `controlplane-db` to a PostgreSQL database, then start the API from a checkout:

```sh
uv sync --project core/user-service --frozen --python 3.13
export DATABASE_URL='postgresql+asyncpg://controlplane:controlplane@127.0.0.1:5432/controlplane'
export KEYCLOAK_ISSUER='http://127.0.0.1:8081/realms/controlplane'
export KEYCLOAK_JWKS_URL='http://127.0.0.1:8081/realms/controlplane/protocol/openid-connect/certs'
export SERVICE_NAME=user-service
export HOST=127.0.0.1
export PORT=8000
uv run --project core/user-service --frozen python -m user_service.main
```

```sh
curl -sS "http://127.0.0.1:8000/api/v1/health/"
curl -sS "http://127.0.0.1:8000/version"
curl -sS "http://127.0.0.1:8000/api/v1/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID"
```

Anonymous calls to `/api/v1/users` are rejected. Optional `USER_SERVICE_CORS_ORIGINS` enables browser CORS. Interactive API docs are served at `/docs`.

Build the image from the repository root. The runtime user is uid 65532 and the command is `python -m user_service.main`. Public dependencies need no GitHub token. A private fork can pass a short-lived read token as the BuildKit secret `dependency_read_token`; that secret is not copied into a layer.

The container has its own loopback interface. `DATABASE_URL` and `KEYCLOAK_JWKS_URL` are opened from inside the container, so they use an address that routes to the host, such as `host.docker.internal` with `--add-host host.docker.internal:host-gateway`. `KEYCLOAK_ISSUER` is the access token `iss` value. When Keycloak minted tokens as `http://127.0.0.1:8081/realms/controlplane`, keep that issuer string while `KEYCLOAK_JWKS_URL` uses `host.docker.internal`. `HOST=0.0.0.0` lets the published port 8000 reach the process. Postgres and Keycloak must listen on the host ports those names reach.

```sh
docker build -f core/user-service/Dockerfile -t user-service:local .
docker run --rm -p 8000:8000 \
  --add-host host.docker.internal:host-gateway \
  -e HOST=0.0.0.0 \
  -e PORT=8000 \
  -e DATABASE_URL='postgresql+asyncpg://controlplane:controlplane@host.docker.internal:5432/controlplane' \
  -e KEYCLOAK_ISSUER='http://127.0.0.1:8081/realms/controlplane' \
  -e KEYCLOAK_JWKS_URL='http://host.docker.internal:8081/realms/controlplane/protocol/openid-connect/certs' \
  -e SERVICE_NAME=user-service \
  user-service:local
```

On Linux, `--network host` puts the container in the host network namespace, so the `127.0.0.1` database and JWKS URLs from the checkout example reach those servers. In that mode the process binds `PORT` on the host directly.

Install the ban contract on its own. Its only runtime dependency is SQLAlchemy `>=2.0.43`.

```sh
uv sync --project core/user-service/contracts --frozen --python 3.13
```

```python
from operator_ban_store import active_ban, subject_banned_sync

banned = await active_ban(session, tenant_id, users=[user_id], groups=[group_id])
# subject_banned_sync(connection, tenant_id, "user", user_id)
```

Operator password reset is two processes. The public route `POST /api/v1/operator/mail/password-reset` needs console and support authority, an active user in the current tenant, a bound Keycloak subject, and a matching email. It returns `sent`, `kind`, `user_id`, and `detail`. It does not return a token or an action URL. The public process sets `PASSWORD_RESET_AUTHORITY_URL`, `PASSWORD_RESET_OPERATIONS_TOKEN`, and an optional `PASSWORD_RESET_AUTHORITY_CA`. The private authority sets the same `PASSWORD_RESET_OPERATIONS_TOKEN`. The public client sends that variable as `X-Password-Reset-Token`. The private app reads `PASSWORD_RESET_OPERATIONS_TOKEN` in `operations_secret()` at startup and on each request; a missing variable raises `PasswordResetUnavailable` before the app serves traffic. Run the private app separately:

```sh
uv run --project core/user-service --frozen \
  python -m uvicorn user_service.password_reset_authority:create_app --factory --host 127.0.0.1 --port 8444
```

That process needs `PASSWORD_RESET_OPERATIONS_TOKEN`, `PASSWORD_RESET_DATABASE_URL` (`postgresql+asyncpg`, `SELECT` on `public.users` and `public.tenants` only), `PASSWORD_RESET_KEYCLOAK_URL`, `PASSWORD_RESET_KEYCLOAK_REALM`, `PASSWORD_RESET_KEYCLOAK_CLIENT_ID=operator-password-reset`, and `PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET`. `PASSWORD_RESET_DATABASE_CA` must name a readable CA certificate file for verified database TLS. The CA requirement is waived only when the database host is loopback and `FASTAPI_ENV` is explicitly `development` or `test`; a container-to-host address is not loopback. Keycloak sends an `UPDATE_PASSWORD` action with a 600-second lifespan. The public app rejects startup if `PASSWORD_RESET_DATABASE_URL` or `PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET` is set in its environment.

The closure worker is off unless both `ACCOUNT_CLOSURE_WORKER_ENABLED=true` and `ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED=true`. It uses `ACCOUNT_CLOSURE_WORKER_DATABASE_URL`, not the public `DATABASE_URL`.

```sh
uv run --project core/user-service --frozen \
  python -m user_service.closure_worker --max-jobs 10
uv run --project core/user-service --frozen \
  python -m user_service.closure_daemon --max-jobs 10 --poll-seconds 30
```

`user_service.closure_authority:app` is the private HTTPS API the public process forwards to. Example environment files are `core/user-service/examples/account-closure.public.env.example` and `core/user-service/examples/account-closure.private.env.example`. To print a private database role plan without connecting:

```sh
python core/user-service/scripts/prepare_closure_database_role.py \
  --role account_closure --database controlplane
```

The command prints a transaction. Apply it with your own database tooling. Personal erasure can also call a verification endpoint when `ACCOUNT_CLOSURE_VERIFICATION_ENABLED=true` together with `ACCOUNT_CLOSURE_VERIFICATION_URL` and `ACCOUNT_CLOSURE_VERIFICATION_TOKEN`.

## How Hypermesh uses it

Hypermesh (`hypermesh-service`) is the lease, device, and host-registration service. It stores leases and host hardware. This service stores the people and the operator decisions about those people.

**Renters and hosts.** A human lease is created with a tenant-session JWT. Hypermesh sets `renter_user_id` from the token subject and requires `can_checkout`. A `purpose=service` exchange JWT may create a lease only when that key is bound to a user. Host registration (`POST /api/v1/hypermesh/host-registrations`, clients `hypermesh-host-setup` or `hypermesh-native`) requires an active tenant membership, membership in the `host` group, and a `host_organization_bindings` row for the Keycloak subject. The portal reads the same person's gates from `GET /api/v1/me/portal-controls`, including `can_see_leases` and `can_see_host_status`.

**Bans on the host path.** `hypermesh-service` depends on `operator-ban-store` from this repository and calls `active_ban` in the host-registration transaction, passing the member id, the subject when it is a UUID, and the caller's host-group ids. A committed ban responds with HTTP 403, `Host registration is blocked by an active ban`. The check uses the caller's session and tenant, so an uncommitted ban is invisible and a committed lift is visible to the next transaction. Other control-plane services use the same boolean. Device bans are a distinct `operator_bans.subject_kind`; host registration asks about users and groups.

**Account still open.** With closure enforcement enabled, shared token validation calls this service:

`POST /api/v1/internal/account-lifecycle/check`

with header `X-Account-Lifecycle-Token` and body `{"subject","tenant_id"}`. A closing lifecycle row or a retirement marker returns `{"blocked": true}`, and the caller rejects the token. Hypermesh's close-owner handler then calls `POST /api/v1/internal/account-lifecycle/scope` and uses the returned `renter_ids` to find that person's leases. `GET /api/v1/internal/account-lifecycle/denials` is the tenant snapshot of retired subjects, key fingerprints, and lease ids.

**Closure traffic toward Hypermesh.** The private worker calls `ACCOUNT_CLOSURE_HYPERMESH_URL` with `X-Account-Lifecycle-Token` and `X-Tenant-ID`:

| Call | What Hypermesh does |
| --- | --- |
| `POST /api/v1/hypermesh/internal/account-lifecycle/close-owner` | Revokes tickets on the renter's leases, pauses devices that are selling, denies pending and approved host registrations, and records model-owner closure. Lease rows and host peers remain. |
| `GET /api/v1/hypermesh/internal/account-lifecycle/gateway-roster` | Returns every gateway id in the tenant. |
| `POST /api/v1/hypermesh/internal/account-lifecycle/purge-models` | Erases model metadata after the scope receipt allows it. |

For each gateway the worker then calls `POST /api/v1/internal/account-lifecycle/deny-principal`, `deny-grants`, `owner-inventory`, and `close-owner` on that gateway's `ACCOUNT_CLOSURE_GATEWAY_<UUID>_URL`. `deny-grants` carries the lease ids and API-key fingerprints from the Hypermesh receipt. Later personal erasure calls `purge-owner` on those gateways and `purge-models` on Hypermesh. In PostgreSQL the worker invokes `hypermesh_erase_personal_host_associations`, `hypermesh_erase_personal_runtime`, and `hypermesh_erase_personal_device_reviewers` for the closed subject.

`GET /api/v1/operator/networks/catalog` reports `hypermesh_url` from settings (default `http://127.0.0.1:8010`) alongside health of the turn, oracles, and payments-access hops.

## Develop and test

Package checks need Python 3.13, uv 0.11.26, and a running Docker daemon. From the repository root, `bash scripts/check-package.sh` locks, installs, and runs the suite from source, from the built wheel, and from a wheel rebuilt from the sdist. Tests start disposable PostgreSQL and Keycloak containers. `bash scripts/check-package.sh --fixtures` runs the same native consumers from the verified wheels under `core/user-service/tests_artifacts/dependencies` and does not need GitHub credentials. `bash scripts/check-container.sh` builds the image and exercises health, version, and authentication against a disposable database named by `TEST_DATABASE_URL`.

The ban contract has its own suite. Point it at a disposable server that may create and drop databases:

```sh
cd core/user-service/contracts
TEST_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@127.0.0.1:5432/postgres' \
  bash scripts/check-package.sh
```

Operator-ban behavior, the closure worker, and the private role plan are described in [core/user-service/README.md](core/user-service/README.md). The contract package is described in [core/user-service/contracts/README.md](core/user-service/contracts/README.md). `integration/source-runtime` checks closure Compose overlays against a Spanopticon runtime snapshot in `CLOSURE_RUNTIME_ROOT`; those manifests are not in this repository. Spanopticon deployment notes are in [hyperme-sh/spanopticon](https://github.com/hyperme-sh/spanopticon).

## Release and versioning

`user-service` and `operator-ban-store` are version **0.1.0**. `release-policy.json` and `releases/candidate/release.json` record line `0.1`. Successful validation on `main` can publish an immutable `0.24.0-test.N` bundle through [.github/test-channel.json](.github/test-channel.json); that bundle name is the coordinated test channel and does not change the 0.1.0 package versions. A stable `vMAJOR.MINOR.PATCH` release is a separate tag and an accepted baseline. Channel rules, qualification artifacts, and stable publication are in [docs/releasing.md](docs/releasing.md). Admission steps are in [docs/release-policy.md](docs/release-policy.md).

## License

First-party service and operator-ban contract code are [Apache-2.0](LICENSE). Both distributions carry SPDX metadata and the license text. Bundled dependencies keep their own licenses.


## Private host-setup authority

The authenticated identity command `POST /api/v1/internal/identity/host-setup`
accepts only a verified opaque subject and target tenant UUID from auth-service.
It reads current active host membership under the tenant GUC and durable user
bans in the user owner's transaction. It returns null when denied or only the
member UUID when allowed; it never returns portal roles or permissions. Direct
host roles and legacy host groups are supported, without email or platform-admin
fallback. Reader-role PostgreSQL/HTTP regressions cover the authorization and ban
boundaries. This endpoint does not activate account closure or deploy a consumer.


The separate `session-member` identity command checks current active tenant and
user membership plus durable user bans for already verified browser-session
facts. Unlike host setup it requires no host role, returns only the member UUID
or null, and never grants portal/host authority. Browser credentials, session
binding and MFA evidence stay in auth and are not sent to the user owner. Both
commands accept only the opaque subject and target tenant from the authenticated
auth-service caller.

The additive `tenant-switch-current` command lets Auth require the current authority during rolling adoption; the existing command also receives the ban check. Tenant switching applies durable user bans in the destination tenant within the owner transaction, including platform overrides and legacy email-bound memberships. Auth must consume that decision without a process-local ban cache.


### Historical identity RLS reconciliation

The immutable historical public schema can cast the empty platform scope to UUID.
Use `python -m user_service.reconcile_identity_rls --database-url-file PRIVATE_FILE
--receipt RECEIPT.json` to inspect the exact four-table/sixteen-policy inventory.
After reviewing that receipt, add `--apply` to repair known predicates atomically.
The tool refuses unknown policy inventories, roles, commands or definitions;
replay is idempotent. It preserves platform/tenant read and write boundaries,
RLS flags and all data. Run it with the database policy owner, outside application
startup. Receipt files contain policy digests, never row contents or credentials.
This does not install historical migrations in runtime wheels or reconcile a live
database automatically. Qualify the exact selected database and runtime separately.


### Explicit network and organization scope contract

The additive `0002_scope_authority.sql` is for a fresh, empty, nonprivileged owner
namespace only. The `scope_schema.install(connection, ddl)` operator entrypoint
verifies its immutable digest and baseline, refuses existing authorization data,
and records an idempotent separate revision without changing `0001` history.
DDL stays outside runtime wheels. Provisioning is a separate private controller;
this contract does not seed or accept a shared TEST generation.

`USER_SCOPE_GENERATION` enables generation-bound scope APIs. The installed marker
must match. It blocks legacy tenant-wide user/operator routes and identity grants
so they cannot bypass the new contract. Network authority comes only from current
subject-bound network grants. Organization member CRUD requires a signed current
org selection plus a live same-org admin membership. Composite foreign keys bind
both the organization and user to the exact tenant. An org membership cannot grant
a tenant or network role. Removing a membership leaves the global user and other
org memberships intact. Disabled, deleted, banned, revoked and inactive-tenant
identities are refused even if older tokens claim admin.

`POST /api/v1/internal/organization-authority/check` exposes current membership,
member-management or purchase authority. AUTH, PAYMENT and PLANE use distinct
`*_SCOPE_AUTHORITY_TOKEN` credentials. Auth may request member/management facts;
Payment and Plane may request member/purchase facts. Duplicate credentials are
refused. No browser token, caller role header or caller email establishes authority.
The response binds subject, user, network, tenant, organization, role, billing
capability, generation and manifest digest. Consumers must recheck current facts.

The owning Infra manifest is canonical. Bootstrap/receipt generation, remaining
consumer adoption, and shared TEST cutover stay separate under issue #63. This
source change does not authorize temporary privileges or repair a live database.
