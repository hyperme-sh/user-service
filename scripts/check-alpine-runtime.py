"""Check the installed Alpine service image without network access."""

from importlib.metadata import distributions
import os
from pathlib import Path
import ssl

from controlplane_identity.account_lifecycle import enforcement_enabled
from psycopg import pq

import user_service.app
import user_service.closure_authority
import user_service.closure_daemon
import user_service.password_reset_authority

assert Path("/etc/alpine-release").is_file()
assert ssl.create_default_context().get_ca_certs(), "System CA store is empty"
assert pq.__impl__ == "binary", "Native psycopg wheel is required"
assert user_service.password_reset_authority.create_app().openapi_url is None
assert not enforcement_enabled()
assert not {"DEPENDENCY_READ_TOKEN", "ACCOUNT_CLOSURE_WORKER_ENABLED"} & os.environ.keys()
assert os.geteuid() == 65532

installed = {distribution.metadata["Name"].lower() for distribution in distributions()}
removed = installed & {"streamlit", "pyarrow", "pandas", "numpy", "pydeck"}
assert not removed, f"Unexpected UI or analytics packages in runtime: {sorted(removed)}"
