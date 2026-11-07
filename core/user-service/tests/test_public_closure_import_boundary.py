"""The public proxy must import without the private owner graph."""
import subprocess
import sys


def test_public_proxy_import_and_default_off_without_private_modules():
    code = '''
import importlib.abc, sys
class RejectPrivate(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'api' or fullname.startswith('api.') or fullname == 'auth_service' or fullname.startswith('auth_service.') or fullname in {'user_service.account_closure', 'user_service.closure_actions', 'user_service.lifecycle_read'}:
            raise RuntimeError('Public closure proxy imported private module: ' + fullname)
sys.meta_path.insert(0, RejectPrivate())
from fastapi import FastAPI
from fastapi.testclient import TestClient
from user_service.closure_proxy import router
app = FastAPI()
app.include_router(router, prefix='/api/v1')
with TestClient(app) as client:
    response = client.post('/api/v1/me/account-closure', json={'confirmation':'CLOSE MY ACCOUNT'})
    assert response.status_code == 503, response.text
    assert response.headers['cache-control'] == 'no-store'
'''
    import os
    environment = dict(os.environ, ACCOUNT_CLOSURE_ACTIONS_ENABLED='false')
    result = subprocess.run([sys.executable, '-I', '-c', code], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
