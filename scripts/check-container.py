"""Exercise the real installed HTTP container on an owned disposable database."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

from controlplane_db.migrations import upgrade
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

image = sys.argv[1]
admin_url = make_url(os.environ['TEST_DATABASE_URL'])
database = 'closure_container_' + uuid.uuid4().hex
admin = create_engine(admin_url, isolation_level='AUTOCOMMIT')
container = None
try:
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{database}"'))
    service_url = admin_url.set(database=database)
    upgrade(service_url.render_as_string(hide_password=False))
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    # Linux qualification uses the host network solely for this loopback-bound
    # disposable DB and HTTP fixture. Deployment remains a separate owner task.
    environment = {**os.environ,
        'DATABASE_URL': service_url.set(drivername='postgresql+asyncpg').render_as_string(hide_password=False),
        'HOST': '127.0.0.1', 'PORT': str(port), 'FASTAPI_ENV': 'test'}
    container = subprocess.check_output(['docker', 'run', '-d', '--network', 'host',
        '-e', 'DATABASE_URL', '-e', 'HOST', '-e', 'PORT', '-e', 'FASTAPI_ENV', image], env=environment, text=True).strip()
    base = f'http://127.0.0.1:{port}'
    deadline = time.monotonic() + 45
    while True:
        try:
            with urllib.request.urlopen(base + '/api/v1/health/', timeout=2) as response:
                assert json.load(response) == {'status': 'Ok'}
            break
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                # No credential-bearing Docker inspection or environment dump.
                raise RuntimeError('Standalone HTTP container did not become healthy') from None
            time.sleep(.25)
    with urllib.request.urlopen(base + '/version', timeout=2) as response:
        assert isinstance(json.load(response), dict)
    try:
        urllib.request.urlopen(base + '/api/v1/users', timeout=2)
    except urllib.error.HTTPError as error:
        assert error.code in (401, 403), error.code
    else:
        raise AssertionError('Anonymous user access succeeded')
    with urllib.request.urlopen(base + '/openapi.json', timeout=2) as response:
        paths = json.load(response)['paths']
        assert '/api/v1/users' in paths
        assert '/internal/ready' not in paths
    try:
        urllib.request.urlopen(urllib.request.Request(base + '/api/v1/internal/account-lifecycle/check', data=b'{}', headers={'Content-Type': 'application/json'}), timeout=2)
    except urllib.error.HTTPError as error:
        assert error.code in (401, 403, 503), error.code
    else:
        raise AssertionError('Anonymous lifecycle forwarding succeeded')
    print('Standalone non-root HTTP container: health, version, auth denial and private-route separation passed')
finally:
    if container:
        subprocess.run(['docker', 'rm', '-f', container], check=True, stdout=subprocess.DEVNULL)
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
    admin.dispose()
