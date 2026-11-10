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
                    VALUES(:key,:tenant,:org,'hyperme.sh','organization','closed-owner')'''),
                    {'key':key,'tenant':tenant,'org':organization})
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
        await db.execute(text('''INSERT INTO api_keys(id,tenant_id,key_prefix,secret_hash,purpose)
            VALUES(:id,:tenant,:prefix,'isolated-not-a-secret','renter')'''),
            {'id':key,'tenant':s.tenant,'prefix':key.hex[:16]})
        with pytest.raises(IntegrityError):
            async with db.begin_nested():
                await db.execute(text('''INSERT INTO api_key_authority_bindings
                    VALUES(:key,:tenant,:org,'hyperme.sh','organization','owner')'''),
                    {'key':key,'tenant':s.tenant,'org':s.wrongorg})
        with pytest.raises(IntegrityError):
            async with db.begin_nested():
                await db.execute(text('''INSERT INTO api_key_authority_bindings
                    VALUES(:key,:tenant,NULL,'hyperme.sh','organization','owner')'''),
                    {'key':key,'tenant':s.tenant})


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
