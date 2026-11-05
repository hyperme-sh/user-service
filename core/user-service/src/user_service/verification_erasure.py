"""Optional verification owner erasure, after the existing closure state machine."""
import os
import httpx
from controlplane_identity.account_lifecycle import service_url, service_secret
from user_service.closure_clients import OwnerUnavailable

async def erase_verification(subject):
    enabled = os.environ.get("ACCOUNT_CLOSURE_VERIFICATION_ENABLED", "false")
    if enabled == "false":
        return {"not_configured": True}
    if enabled != "true" or not os.environ.get("ACCOUNT_CLOSURE_VERIFICATION_URL"):
        raise OwnerUnavailable()
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False, follow_redirects=False) as client:
            response = await client.post(service_url("ACCOUNT_CLOSURE_VERIFICATION_URL") + "/internal/verification/erase",
                headers={"X-Verification-Admin-Token":service_secret("ACCOUNT_CLOSURE_VERIFICATION_TOKEN")}, json={"subject":subject})
            response.raise_for_status()
            if response.json() != {"status":"erased"}:
                raise ValueError()
        return {"complete": True}
    except (httpx.HTTPError, ValueError, TypeError):
        raise OwnerUnavailable() from None
