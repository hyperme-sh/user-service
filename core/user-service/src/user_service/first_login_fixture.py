"""Reversible, owner-only TEST lifecycle for the declared unassociated actor.

Not a public API. Infra must fence acceptance, stop existing sessions, and retain
this private journal through logout/restoration. No identity-provider mutation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

from sqlalchemy import create_engine, text
from user_service.fixture_bootstrap import validate, identifier


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encode(value)); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise ValueError('Private operator-owned journal required')
        return json.load(stream)


def fixture(engine, manifest_raw, bindings_raw, journal, action, *, generation, issuer):
    """Prepare once, or restore idempotently after success or partial failure."""
    manifest, bindings = json.loads(manifest_raw), json.loads(bindings_raw)
    _, tenants, _, accounts, _ = validate(manifest, bindings, generation=generation, issuer=issuer)
    actor = accounts['unassociated']
    if (actor['grants'] or not actor['enabled'] or actor['host_owner']
            or actor['can_purchase_leases'] or actor['tenant_context'] != 'active'):
        raise ValueError('Only the declared enabled unassociated actor is supported')
    digest = hashlib.sha256(manifest_raw).hexdigest()
    binding = dict(generation=generation, manifest_sha256=digest,
                   subjects_sha256=hashlib.sha256(bindings_raw).hexdigest(),
                   subject=actor['id'], email=actor['email'], issuer=issuer)
    journal = Path(journal)
    meta = journal.parent.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
        raise ValueError('Private operator-owned journal directory required')
    if action not in ('prepare', 'restore', 'inspect', 'verify-baseline'):
        raise ValueError('Unknown lifecycle operation')
    with engine.begin() as db:
        flags = db.execute(text('''SELECT r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,
            n.nspowner=r.oid,n.nspname FROM pg_roles r JOIN pg_namespace n
            ON n.nspname=current_schema() WHERE r.rolname=current_user''')).one()
        if any(flags[:4]) or not flags[4] or flags[5] == 'public':
            raise ValueError('Nonprivileged User schema owner required')
        if db.scalar(text("SELECT EXISTS(SELECT 1 FROM pg_constraint p JOIN pg_class c ON c.oid=p.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE p.confrelid='users'::regclass AND n.nspname<>current_schema())")):
            raise ValueError('External User references require an owning lifecycle')
        seal = db.execute(text('SELECT generation,manifest_sha256,subjects_sha256 FROM authority_fixture_generation')).one()
        if tuple(seal) != (generation, digest, binding['subjects_sha256']):
            raise ValueError('Installed TEST seed differs')
        binding['database'] = db.scalar(text('SELECT current_database()'))
        binding['database_oid'] = db.scalar(text('SELECT oid FROM pg_database WHERE datname=current_database()'))
        binding['schema_oid'] = db.scalar(text('SELECT oid FROM pg_namespace WHERE nspname=current_schema()'))
        db.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(:sub,0))'), {'sub': actor['id']})
        # Serialise owner writes while checking references and changing two rows.
        tables = db.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename")).all()
        quote = db.dialect.identifier_preparer.quote
        for table in tables:
            db.exec_driver_sql('LOCK TABLE ' + quote(table) + ' IN SHARE ROW EXCLUSIVE MODE')
        # tenants is the unscoped owner registry. Refuse hidden or undeclared
        # tenant scopes before following any ON DELETE CASCADE edge.
        if db.scalar(text("SELECT relrowsecurity FROM pg_class WHERE oid='tenants'::regclass")):
            raise ValueError('Unscoped tenant inventory required')
        installed = {(str(row.id), row.is_active) for row in db.execute(text('SELECT id,is_active FROM tenants'))}
        expected = {(tenant['id'], tenant['active']) for tenant in tenants.values()}
        if installed != expected:
            raise ValueError('Installed tenant inventory differs from canonical fixtures')
        scopes = [(None, network['id']) for network in manifest['networks']]
        scopes += [(tenant['id'], None) for tenant in tenants.values()]

        def scope(tenant, network=None):
            db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true),set_config('app.current_network_id',:network,true)"),
                       {'tenant': tenant or '', 'network': network or ''})

        def rows():
            values = []
            for tenant in (None, *(t['id'] for t in tenants.values())):
                scope(tenant)
                values += db.scalars(text('SELECT to_jsonb(u) FROM users u WHERE keycloak_sub=:sub OR lower(email)=lower(:email) ORDER BY id'),
                                     {'sub': actor['id'], 'email': actor['email']}).all()
            return sorted(values, key=lambda row: row['id'])

        snapshot = read_private(journal) if journal.exists() else None
        if snapshot is not None and snapshot.get('binding') != binding:
            raise ValueError('Journal belongs to a different fixture')
        current = rows()
        if action in ('prepare', 'verify-baseline'):
            if snapshot is not None:
                raise ValueError('Existing journal requires restoration, never another preparation')
            if (len(current) != 2 or {r['tenant_id'] for r in current} != {None, tenants['active']['id']}
                    or any(r['keycloak_sub'] != actor['id'] or r['email'] != actor['email']
                           or not r['is_active'] or r['deleted_at'] or r['password'] for r in current)
                    or next(r for r in current if r['tenant_id'] is None)['id'] != actor['id']
                    or any(r['id'] != (str(identifier(generation, 'member', tenants['active']['id'], actor['id'])) if r['tenant_id'] else actor['id']) for r in current)
                    or any(r['role_id'] != (str(identifier(generation, 'role', tenants['active']['id'], 'user')) if r['tenant_id'] else None) for r in current)):
                raise ValueError('Canonical unassociated baseline differs')
            scope(None, tenants['active']['network'])
            mapping = db.scalar(text('SELECT to_jsonb(a) FROM authority_fixture_accounts a WHERE user_id=CAST(:id AS uuid)'), {'id': actor['id']})
            if mapping is None or mapping['account_key'] != 'unassociated':
                raise ValueError('Declared fixture binding missing')
            snapshot = dict(binding=binding, users=current, mapping=mapping)
        elif snapshot is None:
            raise ValueError('Original private journal required')
        if action in ('restore', 'inspect') and current == snapshot['users']:
            scope(None, tenants['active']['network'])
            actual = db.scalar(text('SELECT to_jsonb(a) FROM authority_fixture_accounts a WHERE user_id=CAST(:id AS uuid)'), {'id': actor['id']})
            if actual != snapshot['mapping']:
                raise ValueError('Baseline mapping differs')
            if action == 'inspect':
                return {'profile_state': 'baseline', 'changed': False}
            return {'restored': True, 'changed': False}
        if action in ('restore', 'inspect') and (len(current) not in (0, 2) or any(
                r['keycloak_sub'] != actor['id'] or r['email'] != actor['email'] or r['role_id'] is not None
                or not r['is_active'] or r['deleted_at'] or r['sso_provider_id'] != issuer or r['password']
                for r in current) or (current and {r['tenant_id'] for r in current} != {None, tenants['active']['id']})):
            raise ValueError('Unexpected generated profile; preserve journal for investigation')
        # Refuse deletion if any owner relation references this actor or profile.
        # Scan every configured RLS scope, including global and other networks.
        needles = {actor['id'], *(r['id'] for r in current)}
        for tenant, network in scopes:
            scope(tenant, network)
            for table in tables:
                if table in ('users', 'authority_fixture_accounts'):
                    continue
                for needle in needles:
                    if db.scalar(text('SELECT EXISTS(SELECT 1 FROM ' + quote(table) + " r WHERE strpos(to_jsonb(r)::text,:needle)>0)"), {'needle': needle}):
                        raise ValueError('Actor has dependent owner state; no changes made')
        if action == 'verify-baseline':
            return {'profile_state': 'baseline', 'changed': False}
        if action == 'inspect':
            return {'profile_state': 'created-roleless' if current else 'absent', 'changed': False}
        if action == 'prepare':
            write_new(journal, snapshot)  # fsync before committing any deletion
        scope(None, tenants['active']['network'])
        db.execute(text('DELETE FROM authority_fixture_accounts WHERE user_id=CAST(:id AS uuid)'), {'id': actor['id']})
        for tenant in (tenants['active']['id'], None):
            scope(tenant)
            db.execute(text('DELETE FROM users WHERE keycloak_sub=:sub'), {'sub': actor['id']})
        if action == 'restore':
            for row in snapshot['users']:
                scope(row['tenant_id'])
                db.execute(text('INSERT INTO users SELECT * FROM json_populate_record(NULL::users,CAST(:row AS json))'), {'row': json.dumps(row)})
            scope(None, tenants['active']['network'])
            db.execute(text('INSERT INTO authority_fixture_accounts SELECT * FROM json_populate_record(NULL::authority_fixture_accounts,CAST(:row AS json))'),
                       {'row': json.dumps(snapshot['mapping'])})
        return {'restored': action == 'restore', 'changed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'restore', 'inspect', 'verify-baseline'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--subjects', type=Path, required=True)
    parser.add_argument('--journal', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('USER_TEST_FIRST_LOGIN_ENABLED') != '1':
        raise SystemExit('Explicit TEST owner lifecycle selection required')
    raw = args.manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != os.environ.get('USER_TEST_FIXTURE_SHA256'):
        raise SystemExit('Configured TEST manifest differs')
    engine = create_engine(os.environ['USER_FIXTURE_DATABASE_URL'])
    try:
        result = fixture(engine, raw, args.subjects.read_bytes(), args.journal, args.action,
                         generation=os.environ['USER_TEST_FIXTURE_GENERATION'], issuer=os.environ['KEYCLOAK_ISSUER'])
        print(json.dumps(result))
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
