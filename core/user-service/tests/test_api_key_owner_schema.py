"""Actual nonprivileged User-owned key schema, RLS and closure inventory."""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from test_scoped_authority import authority
from user_service.api_key_schema import install
from user_service.scoped_authority import scope


async def test_schema_replay_and_private_exact_subject_inventory(authority):
    s=authority
    install(s.sync);install(s.sync)
    ids=[]
    async with s.maker() as db,db.begin():
        for tenant,organization in ((s.tenant,s.org),(s.isolated,s.wrongorg)):
            async with scope(db,tenant):
                key=uuid.uuid4();ids.append(key)
                await db.execute(text('''INSERT INTO api_keys(id,tenant_id,key_prefix,secret_hash,purpose,created_by_sub)
                    VALUES(:id,:tenant,:prefix,'isolated-not-a-secret','renter','closed-owner')'''),
                    {'id':key,'tenant':tenant,'prefix':key.hex[:16]})
                await db.execute(text('''INSERT INTO api_key_authority_bindings
                    VALUES(:key,:tenant,:org,'hyperme.sh','organization','closed-owner','isolated',:manifest)'''),
                    {'key':key,'tenant':tenant,'org':organization,'manifest':'a'*64})
        async with scope(db,s.tenant):
            found=(await db.execute(text("SELECT * FROM api_key_subject_inventory('closed-owner')"))).mappings().all()
            assert {r['id'] for r in found}==set(ids)
            assert set(found[0])=={'id','tenant_id','key_fingerprint','purpose'}
            assert await db.scalar(text("SELECT current_setting('app.current_tenant_id')"))==str(s.tenant)
            assert not (await db.execute(text("SELECT * FROM api_key_subject_inventory('foreign-owner')"))).all()
        async with scope(db):
            assert await db.scalar(text('SELECT count(*) FROM api_key_authority_bindings'))==0
        async with scope(db,s.tenant):
            assert await db.scalar(text('SELECT count(*) FROM api_key_authority_bindings'))==1
            await db.execute(text("INSERT INTO api_key_owner_closures VALUES(:tenant,'closed-owner',now())"),{'tenant':s.tenant})
        async with scope(db,s.isolated):
            assert await db.scalar(text('SELECT count(*) FROM api_key_owner_closures'))==0


async def test_key_binding_cannot_cross_tenant_or_organization(authority):
    s=authority;install(s.sync)
    async with s.maker() as db,db.begin(),scope(db,s.tenant):
        key=uuid.uuid4()
        await db.execute(text('''INSERT INTO api_keys(id,tenant_id,key_prefix,secret_hash,purpose,created_by_sub)
            VALUES(:id,:tenant,:prefix,'isolated-not-a-secret','renter','owner')'''),
            {'id':key,'tenant':s.tenant,'prefix':key.hex[:16]})
        with pytest.raises(IntegrityError):
            async with db.begin_nested():
                await db.execute(text('''INSERT INTO api_key_authority_bindings
                    VALUES(:key,:tenant,:org,'hyperme.sh','organization','owner','isolated',:manifest)'''),
                    {'key':key,'tenant':s.tenant,'org':s.wrongorg,'manifest':'a'*64})
        with pytest.raises(IntegrityError):
            async with db.begin_nested():
                await db.execute(text('''INSERT INTO api_key_authority_bindings
                    VALUES(:key,:tenant,NULL,'hyperme.sh','organization','owner','isolated',:manifest)'''),
                    {'key':key,'tenant':s.tenant,'manifest':'a'*64})


async def test_inventory_function_has_fixed_path_and_no_public_execute(authority):
    s=authority;install(s.sync)
    async with s.maker() as db,db.begin():
        result=(await db.execute(text('''SELECT p.prosecdef,p.proconfig,p.proacl::text
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname=current_schema() AND p.proname='api_key_subject_inventory' '''))).one()
        assert result[0] and 'pg_catalog' in result[1][0] and 'public' not in result[1][0]
        assert not await db.scalar(text("""SELECT EXISTS(
            SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
            LATERAL aclexplode(p.proacl) a WHERE n.nspname=current_schema()
            AND p.proname='api_key_subject_inventory' AND a.grantee=0
            AND a.privilege_type='EXECUTE')"""))


async def test_execute_only_caller_cannot_shadow_inventory(authority,migrated_sync_url):
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    s=authority;install(s.sync)
    key=uuid.uuid4()
    async with s.maker() as db,db.begin(),scope(db,s.tenant):
        await db.execute(text('''INSERT INTO api_keys(id,tenant_id,key_prefix,secret_hash,purpose,created_by_sub)
            VALUES(:id,:tenant,:prefix,'isolated-not-a-secret','renter','closed-owner')'''),
            {'id':key,'tenant':s.tenant,'prefix':key.hex[:16]})
    caller='key_inventory_'+uuid.uuid4().hex;password=uuid.uuid4().hex
    root=create_engine(migrated_sync_url)
    with root.begin() as db:
        db.exec_driver_sql(f"CREATE ROLE {caller} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS")
    with s.sync.begin() as db:
        schema=db.scalar(text('SELECT current_schema()'))
        quoted=s.sync.dialect.identifier_preparer.quote_identifier(schema)
        db.exec_driver_sql(f'GRANT USAGE ON SCHEMA {quoted} TO {caller}')
        db.exec_driver_sql(f'GRANT EXECUTE ON FUNCTION {quoted}.api_key_subject_inventory(text) TO {caller}')
    engine=create_engine(make_url(migrated_sync_url).set(username=caller,password=password))
    try:
        with engine.begin() as db:
            db.exec_driver_sql('CREATE TEMP TABLE tenants(id uuid)')
            db.exec_driver_sql('CREATE TEMP TABLE api_keys(id uuid,tenant_id uuid,key_fingerprint varchar(64),purpose varchar(32),created_by_sub text)')
            fake=uuid.uuid4()
            db.execute(text('INSERT INTO tenants VALUES(:id)'),{'id':s.tenant})
            db.execute(text("INSERT INTO api_keys VALUES(:id,:tenant,NULL,'renter','closed-owner')"),{'id':fake,'tenant':s.tenant})
            db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':str(s.isolated)})
            rows=db.execute(text(f"SELECT id FROM {quoted}.api_key_subject_inventory('closed-owner')")).scalars().all()
            assert rows==[key] and fake not in rows
            assert db.scalar(text("SELECT current_setting('app.current_tenant_id')"))==str(s.isolated)
    finally:
        engine.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP OWNED BY {caller}')
            db.exec_driver_sql(f'DROP ROLE {caller}')
        root.dispose()


async def test_key_only_writer_needs_no_tenant_mirror_or_directory_grant(authority,migrated_sync_url):
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import DBAPIError
    s=authority;install(s.sync);install(s.sync)
    caller='key_writer_'+uuid.uuid4().hex;password=uuid.uuid4().hex
    root=create_engine(migrated_sync_url)
    with root.begin() as db:
        db.exec_driver_sql(f"CREATE ROLE {caller} LOGIN NOINHERIT PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS")
    with s.sync.begin() as db:
        schema=db.scalar(text('SELECT current_schema()'))
        quoted=s.sync.dialect.identifier_preparer.quote_identifier(schema)
        db.exec_driver_sql(f'GRANT USAGE ON SCHEMA {quoted} TO {caller}')
        db.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE ON {quoted}.api_keys TO {caller}')
        # Prove the hook restores a missing mirror entry without exposing a
        # general tenant-provisioning table to the key runtime.
        db.execute(text('DELETE FROM service_tenants WHERE tenant_id=:tenant'),{'tenant':s.tenant})
    engine=create_engine(make_url(migrated_sync_url).set(username=caller,password=password))
    try:
        with engine.begin() as db:
            db.exec_driver_sql(f'SET LOCAL search_path=pg_catalog,{quoted}')
            db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':str(s.tenant)})
            db.exec_driver_sql('CREATE TEMP TABLE service_tenants(tenant_id uuid) ON COMMIT DROP')
            key=uuid.uuid4()
            db.execute(text("INSERT INTO api_keys(id,tenant_id,key_prefix,secret_hash,purpose,created_by_sub) VALUES(:id,:tenant,:prefix,'isolated','renter','payer')"),
                {'id':key,'tenant':s.tenant,'prefix':key.hex[:16]})
            assert db.scalar(text('SELECT count(*) FROM api_keys WHERE id=:id'),{'id':key})==1
            assert db.scalar(text('SELECT count(*) FROM pg_temp.service_tenants'))==0
            assert not db.scalar(text("SELECT has_table_privilege(current_user,:table,'INSERT')"),{'table':schema+'.service_tenants'})
        with s.sync.begin() as db:
            assert db.scalar(text('SELECT count(*) FROM service_tenants WHERE tenant_id=:tenant'),{'tenant':s.tenant})==1
            trigger=db.execute(text("SELECT p.prosecdef,p.proconfig FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='api_keys'::regclass AND t.tgname='remember_tenant'")).one()
            assert trigger[0] and 'pg_temp' in trigger[1][0]
        with pytest.raises(DBAPIError):
            with engine.begin() as db:db.exec_driver_sql(f'INSERT INTO {quoted}.service_tenants VALUES(gen_random_uuid())')
    finally:
        engine.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP OWNED BY {caller}')
            db.exec_driver_sql(f'DROP ROLE {caller}')
        root.dispose()


async def test_key_schema_advances_recorded_v1_without_rewriting_its_identity(authority):
    import hashlib
    from importlib.resources import files
    s=authority
    first=files('user_service').joinpath('api_key_schema.sql').read_text()
    expected=hashlib.sha256(first.encode()).hexdigest()
    with s.sync.begin() as db:
        schema=s.sync.dialect.identifier_preparer.quote_identifier(db.scalar(text('SELECT current_schema()')))
        db.exec_driver_sql(first.replace('__OWNER_SCHEMA__',schema))
        db.exec_driver_sql('CREATE TABLE api_key_schema_version(revision text PRIMARY KEY,sha256 text NOT NULL)')
        db.execute(text("INSERT INTO api_key_schema_version VALUES('0001_api_key_authority',:digest)"),{'digest':expected})
    install(s.sync);install(s.sync)
    with s.sync.begin() as db:
        versions=db.execute(text('SELECT revision,sha256 FROM api_key_schema_version ORDER BY revision')).all()
        assert versions[0]==('0001_api_key_authority',expected)
        assert versions[1][0]=='0002_api_key_tenant_mirror'
        db.exec_driver_sql("UPDATE api_key_schema_version SET sha256=repeat('f',64) WHERE revision='0001_api_key_authority'")
    with pytest.raises(ValueError,match='identity differs'):install(s.sync)
