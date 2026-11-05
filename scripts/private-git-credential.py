#!/usr/bin/env python3
"""BuildKit-only read credential helper; never persist or log its secret."""
import os
from pathlib import Path
import sys
if sys.argv[1:] != ['get']:
    raise SystemExit(0)
fields = dict(line.rstrip('\n').split('=', 1) for line in sys.stdin if '=' in line)
repos = {'controlplane-api', 'controlplane-core', 'controlplane-db',
         'controlplane-events', 'controlplane-identity', 'controlplane-tenancy',
         'controlplane-models', 'controlplane-tests', 'auth-service', 'user-service'}
if fields.get('protocol') != 'https' or fields.get('host') != 'github.com':
    raise SystemExit(0)
if fields.get('path') not in {f'hyperme-sh/{repo}.git' for repo in repos}:
    raise SystemExit(0)
secret = os.environ.get('DEPENDENCY_READ_TOKEN')
if secret is None:
    try:
        secret = Path('/run/secrets/dependency_read_token').read_text().strip()
    except FileNotFoundError:
        raise SystemExit(0)
if not secret or '\n' in secret or '\r' in secret:
    raise SystemExit('Private dependency read credential is invalid')
print('username=x-access-token')
print(f'password={secret}')
