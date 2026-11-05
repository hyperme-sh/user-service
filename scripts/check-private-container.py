"""Owned container TLS/role qualification; no deployed IdP or mutation claims."""
from datetime import UTC, datetime, timedelta
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, text


def qualify(image, admin, service_url, database):
    role = 'closure_private_' + uuid.uuid4().hex
    password, reader, writer, worker = (secrets.token_hex(32) for _ in range(4))
    subject = 'owned-retirement-' + uuid.uuid4().hex
    tenant = uuid.uuid4()
    spec = importlib.util.spec_from_file_location('private_role_plan', Path(__file__).resolve().parents[1] / 'core/user-service/scripts/prepare_closure_database_role.py')
    plan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plan)
    owned = create_engine(service_url, isolation_level='AUTOCOMMIT')
    container = None
    created = False
    try:
        with owned.connect() as connection:
            statements = plan.render_sql(role, database).splitlines()[1:-1]
            connection.exec_driver_sql(statements[0])
            created = True
            for statement in statements[1:]:
                connection.exec_driver_sql(statement)
            connection.exec_driver_sql(f'ALTER ROLE "{role}" LOGIN PASSWORD \'{password}\'')
        with tempfile.TemporaryDirectory(prefix='closure-tls-fixture-') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'account-closure-authority')])
            now = datetime.now(UTC)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=15))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(key, hashes.SHA256()))
            (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (root/'cert.pem').chmod(0o644)
            (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (root/'key.pem').chmod(0o600)
            # Only these generated fixture files are mounted in this root helper.
            subprocess.run(['docker','run','--rm','--network','none','--user','0:0','--cap-drop','ALL','--cap-add','CHOWN',
                '-v',f'{root}:/fixture',image,'/app/.venv/bin/python','-I','-c',
                "import os; os.chown('/fixture/key.pem',65532,65532)"],check=True,stdout=subprocess.DEVNULL)
            digest = subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
            private_url = service_url.set(drivername='postgresql+asyncpg', username=role, password=password,
                host='host.docker.internal' if service_url.host in ('localhost','127.0.0.1') else service_url.host)
            environment = {**os.environ,
                'ACCOUNT_CLOSURE_IMAGE': 'ghcr.io/hyperme-sh/user-service@' + digest,
                'FASTAPI_ENV':'test', 'ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED':'true',
                'ACCOUNT_CLOSURE_AUTHORITY_ENABLED':'true', 'ACCOUNT_CLOSURE_WORKER_ENABLED':'false',
                'ACCOUNT_CLOSURE_WORKER_DATABASE_URL':private_url.render_as_string(hide_password=False),
                'ACCOUNT_CLOSURE_GUARD_TOKEN':reader, 'ACCOUNT_CLOSURE_OPERATIONS_TOKEN':writer,
                'ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET':worker,
                'ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_ID':'account-closure-worker',
                'ACCOUNT_CLOSURE_KEYCLOAK_URL':'http://127.0.0.1:1',
                'ACCOUNT_CLOSURE_KEYCLOAK_REALM':'owned-fixture',
                'KEYCLOAK_ISSUER':'http://127.0.0.1:1/realms/owned-fixture',
                'ACCOUNT_CLOSURE_TLS_CERT_FILE':'/fixture/cert.pem',
                'ACCOUNT_CLOSURE_TLS_KEY_FILE':'/fixture/key.pem'}
            names = [name for name in environment if name.startswith('ACCOUNT_CLOSURE_') or name in ('KEYCLOAK_ISSUER','FASTAPI_ENV')]
            probe = """
import asyncio, httpx
from sqlalchemy.ext.asyncio import create_async_engine
from user_service.closure_runtime import check_image, certificate_paths
from user_service.closure_worker import check_database, database_url
from user_service.closure_idp import KeycloakClosureClient
stage = 'image'
try:
    check_image()
    stage = 'certificate'
    certificate_paths()
    stage = 'database'
    async def database():
        engine = create_async_engine(database_url())
        try:
            async with asyncio.timeout(10):
                await check_database(engine)
        finally:
            await engine.dispose()
    asyncio.run(database())
    stage = 'identity_configuration'
    KeycloakClosureClient(httpx.AsyncClient(trust_env=False))
except Exception as error:
    print('Private fixture preflight failed: ' + stage + ' ' + type(error).__name__)
    raise SystemExit(1)
"""
            preflight = subprocess.run(['docker','run','--rm','--add-host','host.docker.internal:host-gateway',
                '-v',f'{root}:/fixture:ro',*(item for name in names for item in ('-e',name)),
                image,'/app/.venv/bin/python','-I','-c',probe],env=environment,check=False)
            if preflight.returncode:
                raise RuntimeError('Private fixture preflight did not pass')
            container = subprocess.check_output(['docker','run','-d','--add-host','host.docker.internal:host-gateway',
                '-p','127.0.0.1::8443','-v',f'{root}:/fixture:ro',
                *(item for name in names for item in ('-e',name)),image,
                '/app/.venv/bin/python','-I','-m','user_service.closure_runtime','authority'],env=environment,text=True).strip()
            port = subprocess.check_output(['docker','port',container,'8443/tcp'],text=True).strip().rsplit(':',1)[1]
            base = 'https://127.0.0.1:' + port
            context = ssl.create_default_context(cafile=str(root/'cert.pem'))
            def call(path, *, token=reader, body=None, tenant_id=None):
                headers={'X-Account-Lifecycle-Token':token,'Content-Type':'application/json'}
                if tenant_id is not None:
                    headers['X-Tenant-ID']=str(tenant_id)
                request = urllib.request.Request(base+path, headers=headers,
                    data=None if body is None else json.dumps(body).encode())
                with urllib.request.urlopen(request,context=context,timeout=3) as response:
                    return response.status,json.load(response)
            deadline = time.monotonic()+60
            while True:
                try:
                    assert call('/internal/ready') == (200,{'ready':True})
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        status = subprocess.check_output(['docker','inspect',container,'--format','{{.State.Status}}'],text=True).strip()
                        logs = subprocess.check_output(['docker','logs',container],stderr=subprocess.STDOUT,text=True)
                        # Only fixed diagnostics are surfaced; provider bodies,
                        # SQL parameters, subjects and environment are excluded.
                        summary = [marker for marker in ('Application startup failed','Private account closure runtime unavailable','WorkerUnavailable','PermissionError') if marker in logs]
                        raise RuntimeError('Private TLS container not ready: ' + status + ' ' + ','.join(summary)) from None
                    time.sleep(.25)
            for credential in ('',writer):
                try: call('/internal/ready',token=credential)
                except urllib.error.HTTPError as error: assert error.code == 403
                else: raise AssertionError('Wrong-purpose private credential admitted')
            path='/api/v1/internal/account-lifecycle/check'
            assert call(path,body={'subject':subject}) == (200,{'blocked':False})
            with owned.connect() as connection:
                connection.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,'owned TLS fixture',true)'),{'id':tenant})
                connection.execute(text('INSERT INTO identity_retirements(subject,retired_at) VALUES(:s,now())'),{'s':subject})
            assert call(path,body={'subject':subject}) == (200,{'blocked':True})
            with owned.connect() as connection:
                assert connection.scalar(text('SELECT count(*) FROM account_lifecycles WHERE subject=:s'),{'s':subject}) == 0
            try: call('/api/v1/internal/account-lifecycle/denials',tenant_id=tenant)
            except urllib.error.HTTPError as error: assert error.code == 503
            else: raise AssertionError('Unreconciled retirement claimed a complete snapshot')
            try:
                urllib.request.urlopen(base+'/internal/ready',timeout=3)
            except urllib.error.URLError: pass
            else: raise AssertionError('Untrusted fixture certificate accepted')
            print('Private installed TLS container: limited role, purpose separation, canonical retirement and incomplete-inventory denial passed')
    finally:
        if container:
            subprocess.run(['docker','rm','-f',container],check=True,stdout=subprocess.DEVNULL)
        if created:
            with owned.connect() as connection:
                # Owned database will be dropped by the outer fixture. Remove
                # grants before removing this unique cluster-level test role.
                connection.exec_driver_sql(f'DROP OWNED BY "{role}"')
                connection.exec_driver_sql(f'DROP ROLE "{role}"')

        owned.dispose()
