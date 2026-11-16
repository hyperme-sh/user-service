"""Independent original-run admission for the native tenant-context read."""
import json
import os
from fastapi import Depends, HTTPException
from jwt import InvalidTokenError
from auth_service.deps import bearer_access_token, get_access_token_claims
from controlplane_identity.nightly import require_original_run, require
from controlplane_identity.nightly_http import Authority, RunMiddleware


async def verified_claims(token=Depends(bearer_access_token)):
    from auth_service import deps as native_auth
    claims=await native_auth.get_access_token_claims(token)
    try:require_original_run(claims)
    except (ValueError,InvalidTokenError):raise HTTPException(403,'Original run required') from None
    return claims


def install(app):
    app.dependency_overrides[get_access_token_claims]=verified_claims
    raw=os.environ.get('USER_NIGHTLY_RUN_CONFIG')
    if raw is None:return
    require(len(raw.encode())<=65536)
    app.add_middleware(RunMiddleware,authority=Authority(json.loads(raw),'user'),
        paths={('GET','/api/v1/authority/contexts'),('GET','/api/v1/organizations')},control_path='/api/v1/user/internal/nightly-run')
