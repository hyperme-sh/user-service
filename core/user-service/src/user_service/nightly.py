"""Independent original-run admission for the native tenant-context read."""
import json
import os
import uuid
from fastapi import Depends, HTTPException, Request
from jwt import InvalidTokenError
from auth_service.deps import bearer_access_token, get_access_token_claims, get_current_tenant
from controlplane_identity.nightly import require_original_run, require, current_binding
from controlplane_identity.nightly_http import Authority, RunMiddleware


async def verified_claims(token=Depends(bearer_access_token)):
    from auth_service import deps as native_auth
    claims=await native_auth.get_access_token_claims(token)
    try:require_original_run(claims)
    except (ValueError,InvalidTokenError):raise HTTPException(403,'Original run required') from None
    return claims


async def discovery_tenant(request:Request,claims=Depends(get_access_token_claims)):
    from auth_service import deps as native_auth
    try:
        require_original_run(claims)
        binding=current_binding()
        if binding is not None and request.method=='GET' and request.url.path=='/api/v1/organizations':
            require(request.headers.get('X-Tenant-ID')==binding['scope']['tenant'])
            return uuid.UUID(binding['scope']['tenant'])
    except (ValueError,InvalidTokenError):raise HTTPException(403,'Original tenant required') from None
    return await native_auth.get_current_tenant(claims)


def install(app):
    app.dependency_overrides[get_access_token_claims]=verified_claims
    app.dependency_overrides[get_current_tenant]=discovery_tenant
    raw=os.environ.get('USER_NIGHTLY_RUN_CONFIG')
    if raw is None:return
    require(len(raw.encode())<=65536)
    app.add_middleware(RunMiddleware,authority=Authority(json.loads(raw),'user'),
        paths={('GET','/api/v1/authority/contexts'),('GET','/api/v1/organizations')},control_path='/api/v1/user/internal/nightly-run')
