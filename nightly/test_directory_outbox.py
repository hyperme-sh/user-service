"""Scheduled installed-handler transactions on an Infra-owned disposable schema."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import uuid
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from auth_service.schemas import AuthMeResponse
from controlplane_events.contracts import validate_event_envelope
from controlplane_events.envelope import ControlPlaneEventEnvelope
from user_service.domain.dtos import UserCreateBody
from user_service.interfaces.api import routes


@pytest.fixture
def fixture(monkeypatch):
    source = Path(os.environ['USER_OUTBOX_FIXTURE_SCRIPT'])
    spec = importlib.util.spec_from_file_location('directory_fixture', source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.environment(os.environ)
    subprocess.run([sys.executable, str(source), 'reset-case'], check=True, timeout=60)
    module.authorize_handlers(monkeypatch)
    config = module.configuration()
    url = (Path(os.environ['USER_OUTBOX_FIXTURE_DIR']) / 'owner-url').read_text().strip()
    return module, config, url


def inspect(url, config):
    engine = create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"), {'tenant': config['tenant_id']})
            users = db.execute(text('SELECT count(*) FROM users')).scalar_one()
            members = db.execute(text('SELECT count(*) FROM user_group_memberships')).scalar_one()
            rows = db.execute(text('SELECT id,tenant_id,envelope FROM service_outbox ORDER BY id')).all()
            return users, members, rows
    finally:
        engine.dispose()


async def invoke(operation, session, config):
    tenant = uuid.UUID(config['tenant_id'])
    user = uuid.UUID(config['user_id']); group = uuid.UUID(config['group_id'])
    me = AuthMeResponse(sub=str(user), email=config['email'], tenant_id=tenant, roles=['admin'], scopes=[])
    if operation == 'create':
        return await routes.create_user(UserCreateBody(email=config['new_email'], first_name='New', last_name='User', gender='unspecified', is_active=True), tenant, me, session)
    if operation == 'add':
        return await routes.add_user_to_group(user, group, tenant, me, session)
    return await routes.remove_user_from_group(user, group, tenant, me, session)


def seed_membership(url, config):
    engine = create_engine(url)
    try:
        with engine.begin() as db:
            db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"), {'tenant': config['tenant_id']})
            db.execute(text('INSERT INTO user_group_memberships(id,tenant_id,user_id,group_id) VALUES (:id,:tenant,:user,:group)'),
                       {'id': config['membership_id'], 'tenant': config['tenant_id'], 'user': config['user_id'], 'group': config['group_id']})
    finally:
        engine.dispose()


class RollbackAfterPublish(Exception): pass


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['create', 'add', 'remove'])
@pytest.mark.parametrize('outcome', ['commit', 'rollback', 'insert_failure', 'retry'])
async def test_directory_transaction(fixture, monkeypatch, operation, outcome):
    module, config, url = fixture
    if operation == 'remove': seed_membership(url, config)
    original = routes.publish_directory_event
    async def publish(session, **kwargs):
        first = await original(session, **kwargs)
        if outcome == 'rollback': raise RollbackAfterPublish()
        if outcome == 'retry': assert await original(session, **kwargs) == first
        return first
    monkeypatch.setattr(routes, 'publish_directory_event', publish)
    if outcome == 'insert_failure': module.main('break-outbox')
    engine = create_async_engine(url.replace('postgresql+psycopg://', 'postgresql+asyncpg://'))
    try:
        async def operation_call():
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                async with session.begin():
                    await session.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"), {'tenant': config['tenant_id']})
                    await invoke(operation, session, config)
        if outcome == 'rollback':
            with pytest.raises(RollbackAfterPublish): await operation_call()
        elif outcome == 'insert_failure':
            with pytest.raises(IntegrityError): await operation_call()
        else:
            await operation_call()
    finally:
        await engine.dispose()
    users, members, rows = inspect(url, config)
    success = outcome in ('commit', 'retry')
    assert users == (2 if success and operation == 'create' else 1)
    assert members == (int(success) if operation == 'add' else int(not success) if operation == 'remove' else 0)
    assert len(rows) == int(success)
    for event_id, tenant, payload in rows:
        validate_event_envelope(ControlPlaneEventEnvelope.model_validate(payload))
        assert str(tenant) == payload['tenant_id'] == config['tenant_id']
        assert payload['event_type'] == {'create': 'user.created.v1', 'add': 'group.member.added.v1', 'remove': 'group.member.removed.v1'}[operation]
        assert event_id.version == 5


@pytest.mark.asyncio
async def test_remove_readd_uses_distinct_membership_operations(fixture):
    _, config, url = fixture
    seed_membership(url, config)
    engine = create_async_engine(url.replace('postgresql+psycopg://', 'postgresql+asyncpg://'))
    try:
        for operation in ('remove', 'add', 'remove'):
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                async with session.begin():
                    await session.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"), {'tenant': config['tenant_id']})
                    await invoke(operation, session, config)
    finally: await engine.dispose()
    users, members, rows = inspect(url, config)
    assert users == 1 and members == 0 and len(rows) == 3
    assert len({row[0] for row in rows}) == 3
    config = dict(config, tenant_id=config['other_tenant_id'])
    assert inspect(url, config) == (0, 0, [])
