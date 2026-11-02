"""Apply owner migrations only to a uniquely named disposable database."""
import os
import uuid
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from controlplane_db import migrations

@pytest.fixture(scope='session')
def migrated_postgres():
    base = make_url(os.environ['TEST_DATABASE_URL']).set(drivername='postgresql+psycopg')
    name = 'ban_contract_' + uuid.uuid4().hex
    admin = create_engine(base, isolation_level='AUTOCOMMIT')
    target = base.set(database=name).render_as_string(hide_password=False)
    try:
        with admin.connect() as cx:
            cx.execute(text(f'CREATE DATABASE "{name}"'))
        migrations.upgrade(target, chains=['platform'])
        yield target
    finally:
        with admin.connect() as cx:
            cx.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()

@pytest.fixture(scope='session')
def db_async_url(migrated_postgres):
    return make_url(migrated_postgres).set(drivername='postgresql+asyncpg').render_as_string(hide_password=False)

@pytest.fixture(scope='session')
def rls_isolation_role_ready(migrated_postgres):
    engine = create_engine(migrated_postgres)
    try:
        with engine.begin() as cx:
            cx.execute(text('CREATE ROLE panopticon_rls_tester NOINHERIT NOBYPASSRLS'))
            cx.execute(text('GRANT panopticon_rls_tester TO CURRENT_USER'))
        yield
    finally:
        with engine.begin() as cx:
            cx.execute(text('DROP OWNED BY panopticon_rls_tester'))
            cx.execute(text('DROP ROLE panopticon_rls_tester'))
        engine.dispose()
