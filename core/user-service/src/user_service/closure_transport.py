"""Explicit private-authority CA trust, independent of HTTPX environment trust."""

import os
import ssl


def authority_verify():
    path = os.environ.get("ACCOUNT_CLOSURE_AUTHORITY_CA_FILE", "")
    if not path:
        return True
    try:
        context = ssl.create_default_context(cafile=path)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
    except (OSError, ssl.SSLError):
        raise RuntimeError("Private closure certificate trust unavailable") from None
