"""Real isolated owner transactions; existing identities/grants survive extension."""
import copy
import json
import uuid

import pytest
from sqlalchemy import text

from user_service import fixture_topology as m
from test_fixture_bootstrap import DATA, MANIFEST, bootstrap

DESIRED=json.dumps({**MANIFEST,"tenants":[*MANIFEST["tenants"],m.ADDITION]}).encode()
OP=str(uuid.uuid5(uuid.NAMESPACE_URL,"isolated-user-fixture-topology"))
SOURCE='b'*40


def apply(owner,**kwargs):
    return m.transition(owner,DATA,DESIRED,operation_id=OP,source_sha=SOURCE,**kwargs)


def generation(owner):
    with owner.begin() as db:return tuple(db.execute(text('SELECT manifest_sha256,source_sha,seeded_at FROM authority_fixture_generation')).one())


def test_plan_refuses_any_account_grant_or_tenant_drift():
    assert m.plan(DATA,DESIRED)['addition']==m.ADDITION
    for change in ('accounts','extra-tenant','active-tenant','new-id'):
        candidate=json.loads(DESIRED)
        if change=='accounts':candidate['accounts'][0]['enabled']=False
        elif change=='extra-tenant':candidate['tenants'].append(copy.deepcopy(m.ADDITION))
        elif change=='active-tenant':candidate['tenants'][0]['name']='changed'
        else:candidate['tenants'][-1]['id']=str(uuid.uuid4())
        with pytest.raises(ValueError):m.plan(DATA,json.dumps(candidate).encode())


def test_atomic_extension_and_post_commit_retry_are_noop(empty_authority_owner):
    owner=empty_authority_owner;bootstrap(owner);before=generation(owner)
    with owner.begin() as db:fingerprint=m.protected(db,MANIFEST)
    receipt=apply(owner)
    assert receipt['protected_sha256']==fingerprint
    assert receipt['runtime_accepted'] is False
    assert apply(owner)==receipt
    assert generation(owner)==(m.sha(DESIRED),before[1],before[2])
    with owner.begin() as db:
        assert db.scalar(text('SELECT count(*) FROM authority_fixture_transitions'))==1
        assert m.protected(db,MANIFEST)==fingerprint
    assert apply(owner,action='rollback')['state']=='rolled-back'
    assert generation(owner)==before
    assert apply(owner,action='rollback')['state']=='rolled-back'
    with pytest.raises(ValueError):apply(owner)


def test_interruption_rolls_back_tenant_and_journal(empty_authority_owner,monkeypatch):
    owner=empty_authority_owner;bootstrap(owner);before=generation(owner)
    original=m.protected;calls=[]
    def fail(db,manifest):
        calls.append(True)
        if len(calls)==2:raise RuntimeError('isolated failure after owner insert')
        return original(db,manifest)
    with monkeypatch.context() as context:
        context.setattr(m,'protected',fail)
        with pytest.raises(RuntimeError):apply(owner)
    assert generation(owner)==before
    with owner.begin() as db:assert db.scalar(text('SELECT count(*) FROM tenants'))==2
    assert apply(owner)['state']=='applied'


def test_rollback_refuses_consumed_tenant_without_erasing_state(empty_authority_owner):
    owner=empty_authority_owner;bootstrap(owner);apply(owner)
    user=uuid.uuid4();tenant=uuid.UUID(m.ADDITION['id'])
    with owner.begin() as db:
        m.scope(db,tenant)
        db.execute(text("INSERT INTO users(id,tenant_id,email,first_name,last_name,gender,is_active) VALUES(:id,:tenant,'synthetic@example.invalid','Isolated','Fixture','unspecified',true)"),{'id':user,'tenant':tenant})
    with pytest.raises(ValueError,match='in use'):apply(owner,action='rollback')
    with owner.begin() as db:
        m.scope(db,tenant);assert db.scalar(text('SELECT count(*) FROM users WHERE id=:id'),{'id':user})==1
    assert generation(owner)[0]==m.sha(DESIRED)


def test_unexpected_live_topology_and_operation_reuse_refuse(empty_authority_owner):
    owner=empty_authority_owner;bootstrap(owner)
    with owner.begin() as db:db.execute(text("UPDATE tenants SET name='Changed tenant' WHERE id=:id"),{'id':uuid.UUID(MANIFEST['tenants'][0]['id'])})
    with pytest.raises(ValueError,match='Unexpected live'):apply(owner)
    with owner.begin() as db:db.execute(text('UPDATE tenants SET name=:name WHERE id=:id'),{'id':uuid.UUID(MANIFEST['tenants'][0]['id']),'name':MANIFEST['tenants'][0]['name']})
    apply(owner)
    with pytest.raises(ValueError,match='Operation identity'):
        m.transition(owner,DATA,DESIRED,operation_id=OP,source_sha='c'*40)


def test_rollback_refuses_modified_metadata(empty_authority_owner):
    owner=empty_authority_owner;bootstrap(owner);apply(owner)
    with owner.begin() as db:
        m.scope(db,m.ADDITION['id'])
        db.execute(text("UPDATE roles SET permissions='[\"modified\"]'::jsonb WHERE tenant_id=:id AND name='user'"),{'id':uuid.UUID(m.ADDITION['id'])})
    with pytest.raises(ValueError,match='metadata changed'):apply(owner,action='rollback')
    assert generation(owner)[0]==m.sha(DESIRED)


@pytest.mark.parametrize("table,column,value", [
    ("tenants","custom_domain","changed.example.invalid"),
    ("tenants","features",'{"changed":true}'),
    ("roles","description","preserve role edit"),
    ("groups","description","preserve group edit"),
])
def test_rollback_preserves_all_inserted_metadata_edits(empty_authority_owner,table,column,value):
    owner=empty_authority_owner;bootstrap(owner);apply(owner)
    key='id' if table=='tenants' else 'tenant_id'
    with owner.begin() as db:
        m.scope(db,m.ADDITION['id'])
        expression='CAST(:value AS jsonb)' if column=='features' else ':value'
        db.execute(text(f'UPDATE {table} SET {column}={expression} WHERE {key}=:id'),{'id':uuid.UUID(m.ADDITION['id']),'value':value})
    with pytest.raises(ValueError,match='metadata changed'):apply(owner,action='rollback')
    with owner.begin() as db:
        m.scope(db,m.ADDITION['id'])
        assert db.scalar(text(f'SELECT count(*) FROM {table} WHERE {key}=:id'),{'id':uuid.UUID(m.ADDITION['id'])})>0


@pytest.mark.parametrize('table,key',[('event_inbox','event_id'),('service_outbox','id')])
def test_rollback_observes_writer_committed_while_acquiring_locks(empty_authority_owner,table,key):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from sqlalchemy import event
    owner=empty_authority_owner;bootstrap(owner);apply(owner)
    attempted=threading.Event()
    def at_lock(connection,cursor,statement,*args):
        if statement==f'LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE':attempted.set()
    event.listen(owner,'before_cursor_execute',at_lock)
    writer=owner.connect();tx=writer.begin()
    row=uuid.uuid4()
    try:
        m.scope(writer,m.ADDITION['id'])
        writer.execute(text(f'INSERT INTO {table}({key},tenant_id,envelope) VALUES(:id,:tenant,\'{{}}\'::jsonb)'),{'id':row,'tenant':uuid.UUID(m.ADDITION['id'])})
        with ThreadPoolExecutor(max_workers=1) as executor:
            future=executor.submit(apply,owner,action='rollback')
            assert attempted.wait(10),'rollback never reached the contended table'
            tx.commit()
            with pytest.raises(ValueError,match='in use'):future.result(timeout=10)
        with owner.begin() as db:
            m.scope(db,m.ADDITION['id'])
            assert db.scalar(text(f'SELECT count(*) FROM {table} WHERE {key}=:id'),{'id':row})==1
        assert generation(owner)[0]==m.sha(DESIRED)
    finally:
        if tx.is_active:tx.rollback()
        writer.close();event.remove(owner,'before_cursor_execute',at_lock)


def test_rollback_after_uncommitted_intent_is_harmless(empty_authority_owner):
    owner=empty_authority_owner;bootstrap(owner);before=generation(owner)
    assert apply(owner,action='rollback')['state']=='not-applied'
    assert generation(owner)==before


@pytest.mark.parametrize("table, key, change", [
    ("roles", "tenant_id", "description='modified'"),
    ("tenants", "id", "custom_domain='modified.invalid'"),
    ("tenants", "id", "features=jsonb_build_object('modified',true)"),
])
def test_rollback_preserves_edited_owner_metadata(empty_authority_owner, table, key, change):
    owner = empty_authority_owner
    bootstrap(owner)
    apply(owner)
    tenant = uuid.UUID(m.ADDITION["id"])
    with owner.begin() as db:
        m.scope(db, tenant)
        db.execute(text(f"UPDATE {table} SET {change} WHERE {key}=:id"), {"id": tenant})
    with pytest.raises(ValueError, match="metadata changed"):
        apply(owner, action="rollback")
    assert generation(owner)[0] == m.sha(DESIRED)


def test_rollback_sees_writer_committed_before_table_lock(empty_authority_owner):
    from sqlalchemy import event

    owner = empty_authority_owner
    bootstrap(owner)
    apply(owner)
    tenant = uuid.UUID(m.ADDITION["id"])
    event_id = uuid.uuid4()

    def commit_event(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("LOCK TABLE event_inbox "):
            with owner.begin() as writer:
                m.scope(writer, tenant)
                writer.execute(text("INSERT INTO event_inbox(event_id,tenant_id,envelope) "
                                    "VALUES(:event,:tenant,'{}')"), {"event": event_id, "tenant": tenant})

    event.listen(owner, "before_cursor_execute", commit_event)
    try:
        with pytest.raises(ValueError, match="in use.*event_inbox"):
            apply(owner, action="rollback")
    finally:
        event.remove(owner, "before_cursor_execute", commit_event)
    assert generation(owner)[0] == m.sha(DESIRED)
    with owner.begin() as db:
        m.scope(db, tenant)
        assert db.scalar(text("SELECT count(*) FROM event_inbox WHERE event_id=:event"), {"event": event_id}) == 1


def test_schema_marker_drift_refuses_before_topology_mutation(empty_authority_owner):
    owner=empty_authority_owner;bootstrap(owner);before=generation(owner)
    with owner.begin() as db:db.execute(text("UPDATE owner_authority_version SET sha256=:digest"),{'digest':'0'*64})
    with pytest.raises(ValueError,match='authority schema'):apply(owner)
    assert generation(owner)==before
    with owner.begin() as db:assert db.scalar(text('SELECT count(*) FROM tenants'))==2
