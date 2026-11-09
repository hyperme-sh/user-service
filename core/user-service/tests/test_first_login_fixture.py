"""Owner-supported reversible fixture, using real FORCE-RLS PostgreSQL."""
import json
import uuid
from types import SimpleNamespace
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from test_fixture_bootstrap import bootstrap, DATA, BINDINGS, MANIFEST, ISSUER
from user_service.first_login_fixture import fixture


def invoke(owner, journal, action, manifest=DATA):
    return fixture(owner, manifest, BINDINGS, journal, action,
                   generation=MANIFEST['generation'], issuer=ISSUER)


def actor():
    return next(a for a in MANIFEST['accounts'] if a['key'] == 'unassociated')


def profile(owner):
    tenant = next(t['id'] for t in MANIFEST['tenants'] if t['key'] == 'active')
    with owner.begin() as db:
        db.execute(text("SELECT set_config('app.current_tenant_id',:t,true)"), {'t': tenant})
        return db.scalar(text('SELECT to_jsonb(u) FROM users u WHERE keycloak_sub=:s'), {'s': actor()['id']})


async def test_normal_login_after_prepare_and_exact_idempotent_restoration(empty_authority_owner, tmp_path, monkeypatch):
    from user_service.scope_adapter import establish_login_tenant
    owner = empty_authority_owner
    bootstrap(owner)
    journal = tmp_path / 'original.json'
    assert invoke(owner, journal, 'verify-baseline') == {'profile_state':'baseline', 'changed':False}
    assert invoke(owner, journal, 'prepare') == {'restored': False, 'changed': True}
    assert profile(owner) is None
    with pytest.raises(ValueError, match='requires restoration'):
        invoke(owner, journal, 'verify-baseline')
    assert invoke(owner, journal, 'inspect')['profile_state'] == 'absent'
    assert journal.stat().st_mode & 0o777 == 0o600
    tenant = next(t['id'] for t in MANIFEST['tenants'] if t['key'] == 'active')
    monkeypatch.setenv('USER_SCOPED_AUTHORITY_REQUIRED', '1')
    monkeypatch.setenv('USER_LOGIN_TENANT_ID', tenant)
    monkeypatch.setenv('KEYCLOAK_ISSUER', ISSUER)
    monkeypatch.setenv('USER_LOGIN_CLIENT_ID', 'portal')
    engine = create_async_engine(owner.url.set(drivername='postgresql+asyncpg'))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_maker=async_sessionmaker(engine))))
    claims = dict(iss=ISSUER, azp='portal', sub=actor()['id'], email=actor()['email'], email_verified=True)
    try:
        assert (await establish_login_tenant(request, claims)).status_code == 204
        created = profile(owner)
        assert invoke(owner, journal, 'inspect')['profile_state'] == 'created-roleless'
        assert created['role_id'] is None and created['sso_provider_id'] == ISSUER
        assert (await establish_login_tenant(request, claims)).status_code == 204
        assert profile(owner) == created
    finally:
        await engine.dispose()
    assert invoke(owner, journal, 'restore') == {'restored': True, 'changed': True}
    assert invoke(owner, journal, 'inspect')['profile_state'] == 'baseline'
    original = json.loads(journal.read_text())['users']
    assert profile(owner) == next(r for r in original if r['tenant_id'])
    assert invoke(owner, journal, 'restore') == {'restored': True, 'changed': False}
    with pytest.raises(ValueError, match='requires restoration'):
        invoke(owner, journal, 'prepare')


def test_aborted_prepare_and_empty_profile_restore(empty_authority_owner, tmp_path):
    owner = empty_authority_owner
    bootstrap(owner)
    journal = tmp_path / 'original.json'
    invoke(owner, journal, 'prepare')
    assert invoke(owner, journal, 'restore')['restored'] is True
    # Durable intent written before a database commit is safe to restore again.
    assert invoke(owner, journal, 'restore')['changed'] is False


def test_dependent_owner_state_refuses_without_writing_journal(empty_authority_owner, tmp_path):
    owner = empty_authority_owner
    bootstrap(owner)
    before = profile(owner)
    tenant = before['tenant_id']
    with owner.begin() as db:
        db.execute(text("SELECT set_config('app.current_tenant_id',:t,true)"), {'t': tenant})
        group = db.scalar(text("SELECT id FROM groups WHERE name='renter'"))
        db.execute(text('INSERT INTO user_group_memberships(id,user_id,group_id,tenant_id) VALUES(:id,CAST(:u AS uuid),:g,CAST(:t AS uuid))'),
                   {'id':uuid.uuid4(), 'u': before['id'], 'g': group, 't': tenant})
    journal = tmp_path / 'original.json'
    with pytest.raises(ValueError, match='dependent owner state'):
        invoke(owner, journal, 'prepare')
    assert not journal.exists() and profile(owner) == before


@pytest.mark.parametrize('change', ['wrong-actor', 'wrong-seed', 'public-directory'])
def test_invalid_fixture_refused(empty_authority_owner, tmp_path, change):
    owner = empty_authority_owner
    bootstrap(owner)
    before = profile(owner)
    manifest = json.loads(DATA)
    if change == 'wrong-actor':
        next(a for a in manifest['accounts'] if a['key'] == 'unassociated')['host_owner'] = True
    if change == 'wrong-seed':
        manifest['accounts'][0]['email'] = 'different@example.invalid'
    if change == 'public-directory':
        tmp_path.chmod(0o755)
    with pytest.raises(ValueError):
        invoke(owner, tmp_path / 'original.json', 'prepare', json.dumps(manifest).encode())
    assert profile(owner) == before


def test_crash_after_journal_write_rolls_back_and_can_restore(empty_authority_owner, tmp_path, monkeypatch):
    import user_service.first_login_fixture as module
    owner = empty_authority_owner
    bootstrap(owner)
    before = profile(owner)
    original = module.write_new
    def interrupted(path, value):
        original(path, value)
        raise OSError('simulated interruption after fsync')
    monkeypatch.setattr(module, 'write_new', interrupted)
    journal = tmp_path / 'original.json'
    with pytest.raises(OSError, match='interruption'):
        invoke(owner, journal, 'prepare')
    assert journal.exists() and profile(owner) == before
    assert invoke(owner, journal, 'restore') == {'restored': True, 'changed': False}


def test_wrong_journal_and_missing_original_never_reconstruct_seed(empty_authority_owner, tmp_path):
    owner = empty_authority_owner
    bootstrap(owner)
    before = profile(owner)
    journal = tmp_path / 'original.json'
    with pytest.raises(ValueError, match='Original private journal'):
        invoke(owner, journal, 'restore')
    journal.write_text(json.dumps({'binding': {'generation': 'wrong'}}))
    journal.chmod(0o600)
    with pytest.raises(ValueError, match='different fixture'):
        invoke(owner, journal, 'restore')
    assert profile(owner) == before
