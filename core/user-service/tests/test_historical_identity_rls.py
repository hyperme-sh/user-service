"""Reconcile immutable historical policies using real non-bypass PostgreSQL roles."""
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from user_service.reconcile_identity_rls import reconcile, _snapshot, _digest


@pytest.fixture
def historical_identity(postgres_sync_url):
    from controlplane_db.migrations import upgrade
    database = 'identity_history_' + uuid.uuid4().hex
    reader = 'identity_reader_' + uuid.uuid4().hex
    password = uuid.uuid4().hex
    admin = create_engine(postgres_sync_url, isolation_level='AUTOCOMMIT')
    with admin.connect() as db:
        db.execute(text(f'CREATE DATABASE "{database}"'))
        db.execute(text(f'CREATE ROLE "{reader}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS'))
    url = make_url(postgres_sync_url).set(database=database)
    engine = create_engine(url)
    restricted = create_engine(url.set(username=reader,password=password))
    try:
        upgrade(url.render_as_string(hide_password=False), chains=['platform','events'])
        with engine.begin() as db:
            db.execute(text(f'GRANT USAGE ON SCHEMA public TO "{reader}"'))
            db.execute(text(f'GRANT SELECT,INSERT,UPDATE,DELETE ON users,roles,groups,user_group_memberships TO "{reader}"'))
        yield engine, restricted
    finally:
        restricted.dispose(); engine.dispose()
        with admin.connect() as db:
            db.execute(text(f'DROP DATABASE "{database}" WITH (FORCE)'))
            db.execute(text(f'DROP ROLE "{reader}"'))
        admin.dispose()


def seed(engine):
    a,b=uuid.uuid4(),uuid.uuid4()
    with engine.begin() as db:
        for tenant in (a,b):
            db.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'), {'id':tenant,'name':str(tenant)})
        for tenant,name in [(None,'platform'),(a,'a'),(b,'b')]:
            db.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,:name,'[]'::jsonb)"), {'id':uuid.uuid4(),'tenant':tenant,'name':name})
    return a,b


def test_historical_platform_cast_repaired_without_broadening_scope(historical_identity):
    engine,reader=historical_identity
    a,b=seed(engine)
    with pytest.raises(DBAPIError, match='invalid input syntax for type uuid'):
        with reader.begin() as db:
            db.execute(text("SELECT set_config('app.current_tenant_id','',true)"))
            db.execute(text('SELECT name FROM roles')).all()
    with engine.begin() as db:
        pending=reconcile(db)
        assert pending['status']=='pending' and pending['before_sha256']==pending['after_sha256']
        fixed=reconcile(db,apply=True)
        assert fixed['changed']==16 and fixed['status']=='reconciled'
        current=reconcile(db,apply=True)
        assert current['status']=='current' and current['changed']==0
        assert current['after_sha256']==fixed['after_sha256']
    for scope,names in [('',{'platform'}),(str(a),{'a'}),(str(b),{'b'})]:
        with reader.begin() as db:
            assert db.execute(text('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user')).scalar() is False
            db.execute(text("SELECT set_config('app.current_tenant_id',:scope,true)"),{'scope':scope})
            assert set(db.execute(text('SELECT name FROM roles')).scalars())==names


@pytest.mark.parametrize('platform',[False,True])
def test_historical_write_policies_preserve_scope(historical_identity,platform):
    engine,reader=historical_identity
    a,b=seed(engine)
    with engine.begin() as db:
        reconcile(db,apply=True)
    own=None if platform else a
    scope='' if platform else str(a)
    new=uuid.uuid4()
    with reader.begin() as db:
        db.execute(text("SELECT set_config('app.current_tenant_id',:scope,true)"),{'scope':scope})
        db.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,'new','[]'::jsonb)"),{'id':new,'tenant':own})
        assert db.execute(text("UPDATE roles SET name='updated' WHERE id=:id"),{'id':new}).rowcount==1
        assert db.execute(text('DELETE FROM roles WHERE tenant_id=:foreign'),{'foreign':b}).rowcount==0
    for operation in ['insert','update']:
        with pytest.raises(DBAPIError,match='row-level security'):
            with reader.begin() as db:
                db.execute(text("SELECT set_config('app.current_tenant_id',:scope,true)"),{'scope':scope})
                if operation=='insert':
                    db.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,'foreign','[]'::jsonb)"),{'id':uuid.uuid4(),'tenant':b})
                else:
                    db.execute(text('UPDATE roles SET tenant_id=:tenant WHERE id=:id'),{'tenant':b,'id':new})
    with reader.begin() as db:
        db.execute(text("SELECT set_config('app.current_tenant_id',:scope,true)"),{'scope':scope})
        assert db.execute(text('DELETE FROM roles WHERE id=:id'),{'id':new}).rowcount==1


def test_unknown_policy_inventory_or_definition_is_never_overwritten(historical_identity):
    engine,_=historical_identity
    with engine.begin() as db:
        db.exec_driver_sql('ALTER POLICY tenant_isolation_delete ON public.users USING (false)')
        before=_digest(_snapshot(db))
        with pytest.raises(ValueError,match='definition differs'):
            reconcile(db,apply=True)
        assert _digest(_snapshot(db))==before
        db.exec_driver_sql('CREATE POLICY unexpected ON public.roles USING (true)')
        before=_digest(_snapshot(db))
        with pytest.raises(ValueError,match='inventory differs'):
            reconcile(db,apply=True)
        assert _digest(_snapshot(db))==before


def test_reconciliation_rolls_back_with_caller_transaction(historical_identity):
    engine,_=historical_identity
    with engine.begin() as db:
        before=_digest(_snapshot(db))
    with pytest.raises(RuntimeError,match='abort'):
        with engine.begin() as db:
            assert reconcile(db,apply=True)['changed']==16
            raise RuntimeError('abort')
    with engine.begin() as db:
        assert _digest(_snapshot(db))==before
