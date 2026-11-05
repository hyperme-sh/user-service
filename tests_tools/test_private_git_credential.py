"""Credential helper boundaries for public builds and explicit private forks."""
import os
from pathlib import Path
import subprocess
import sys

HELPER = Path(__file__).resolve().parents[1] / 'scripts/private-git-credential.py'

def invoke(host='github.com', path='hyperme-sh/controlplane-identity.git', token=None):
    env = {k: v for k, v in os.environ.items() if k != 'DEPENDENCY_READ_TOKEN'}
    if token is not None:
        env['DEPENDENCY_READ_TOKEN'] = token
    return subprocess.run([sys.executable, str(HELPER), 'get'],
        input=f'protocol=https\nhost={host}\npath={path}\n\n',
        text=True, capture_output=True, env=env)

def test_absent_secret_allows_anonymous_git():
    assert not Path('/run/secrets/dependency_read_token').exists()
    result = invoke()
    assert result.returncode == 0
    assert result.stdout == result.stderr == ''

def test_explicit_secret_is_restricted_to_allowed_repository():
    assert invoke(token='test-only').stdout == 'username=x-access-token\npassword=test-only\n'
    assert invoke(host='example.com', token='test-only').stdout == ''
    assert invoke(path='hyperme-sh/unlisted.git', token='test-only').stdout == ''

def test_malformed_explicit_secret_is_rejected_without_disclosure():
    result = invoke(token='invalid\nvalue')
    assert result.returncode != 0
    assert result.stdout == ''
    assert 'invalid\nvalue' not in result.stderr
