# External source-runtime checks

The two Compose cases validate the unchanged source runtime overlay against its
actual base and VM manifests. They are external integration checks, separate
from the installed user-service suite. Set CLOSURE_RUNTIME_ROOT to the reviewed
source snapshot containing all three manifests. Missing inputs fail the check.
These checks do not qualify a separated plane deployment or enable closure.

The separated deployment owner is hyperme-sh/spanopticon. Its runtime delivery
and consumer adoption remain an activation gate; copying a legacy deployment
into this service would not establish that integration.
