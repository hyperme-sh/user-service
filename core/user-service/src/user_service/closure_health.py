"""Authenticated TLS readiness probe; never print configuration or responses."""

import asyncio

import httpx
from controlplane_identity.account_lifecycle import service_secret, service_url

from user_service.closure_transport import authority_verify


async def check():
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=3,
                                     verify=authority_verify()) as client:
            response = await client.get(service_url("ACCOUNT_CLOSURE_AUTHORITY_URL") + "/internal/ready",
                headers={"X-Account-Lifecycle-Token": service_secret("ACCOUNT_CLOSURE_GUARD_TOKEN")})
        return response.status_code == 200 and response.json() == {"ready": True}
    except Exception:  # noqa: BLE001 - no TLS/database/credential diagnostics on probe output
        return False


def main():
    return 0 if asyncio.run(check()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
