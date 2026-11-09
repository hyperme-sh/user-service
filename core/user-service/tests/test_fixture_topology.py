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
    assert generation(owner)==(m.sha(DESIRED),SOURCE,before[2])
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
