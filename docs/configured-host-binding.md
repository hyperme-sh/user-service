# Configured host enrollment binding

Configured enrollment reads current User authority and never grants a host role.
When the caller requests an existing host capability, it also calls the Plane
owner's authenticated host-organization resolver before reporting a host grant.
The returned organization must equal the current declared User organization.
A missing owner, rejected request or different organization fails enrollment.

The Plane's scoped resolver reserves only that tenant and immutable subject's
configured organization. It refuses an existing different binding and does not
create another organization. Lost replies can be retried through normal host
enrollment. Renter-only requests and callers without configured host authority
never call the resolver. No SQL repair or temporary role grant is needed.

The regression fixture creates only disposable PostgreSQL state and uses a local
HTTP mock, with no credentials or network. Testcontainers removes its own database;
engine disposal and per-test owner cleanup retain no shared state. Commit this
fixture definition before running it. Source/package qualification is separate
from live TEST binding reconciliation and native paused host acceptance.


Development CI records the actual two-wheel owner archive and exported complete
runtime contract in its retained `qualification/` directory, bound to the exact
checkout SHA with `stable_release=false`. The existing strict candidate verifier
checks those current bytes. Historical checked-in candidates remain unchanged;
they describe their selected bytes and cannot equal every later development
build. Release admission and owner selection remain separate. The tooling
regression retains an old candidate, changes runtime bytes, verifies the fresh
qualification, and confirms the old record still rejects those new bytes.
