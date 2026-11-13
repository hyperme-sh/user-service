"""Unit contracts for the directory writer; no database or external services."""
import ast
from pathlib import Path
import uuid
from types import SimpleNamespace
import pytest
from controlplane_events.payloads import UserCreatedEvent, GroupMemberAddedPayload, GroupMemberRemovedPayload
from user_service.outbox import publish_directory_event

TENANT = uuid.UUID('00000000-0000-4000-8000-000000009501')
USER = uuid.UUID('00000000-0000-4000-8000-000000009502')
GROUP = uuid.UUID('00000000-0000-4000-8000-000000009503')


def cases():
    return [
        ('user.created.v1', UserCreatedEvent(user_id=USER, email='user@example.com', tenant_id=str(TENANT)).to_envelope_payload()),
        ('group.member.added.v1', GroupMemberAddedPayload(user_id=USER, group_id=GROUP, tenant_id=TENANT).to_envelope_payload()),
        ('group.member.removed.v1', GroupMemberRemovedPayload(user_id=USER, group_id=GROUP, tenant_id=TENANT).to_envelope_payload()),
    ]


class Session:
    def __init__(self):
        self.rows = {}
        self.info = {'directory_event_sink': []}
        self.fail = False
    async def execute(self, statement, values):
        if self.fail:
            raise RuntimeError('insert refused')
        key = values['id']
        if str(statement).lstrip().startswith('INSERT'):
            duplicate = key in self.rows
            if not duplicate:
                self.rows[key] = values['envelope']
            return SimpleNamespace(scalar_one_or_none=lambda: None if duplicate else key)
        return SimpleNamespace(scalar_one=lambda: self.rows[key])


@pytest.mark.asyncio
@pytest.mark.parametrize('event_type,payload', cases())
async def test_retry_uses_one_id_and_rejects_changed_operation(event_type, payload):
    session = Session()
    kwargs = dict(tenant_id=TENANT, event_type=event_type, operation_id=USER, payload=payload)
    first = await publish_directory_event(session, **kwargs)
    assert await publish_directory_event(session, **kwargs) == first
    assert len(session.rows) == len(session.info['directory_events']) == 1
    assert session.rows[first]['tenant_id'] == str(TENANT)
    session.rows[first]['payload'] = {'changed': True}
    with pytest.raises(ValueError, match='conflicts'):
        await publish_directory_event(session, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize('event_type,payload', cases())
async def test_insert_failure_propagates_to_business_transaction(event_type, payload):
    session = Session(); session.fail = True
    with pytest.raises(RuntimeError, match='refused'):
        await publish_directory_event(session, tenant_id=TENANT, event_type=event_type, operation_id=USER, payload=payload)
    assert session.rows == {}
    assert 'directory_events' not in session.info


def test_all_production_publishers_require_the_business_session():
    root = Path(__file__).resolve().parents[1] / 'src/user_service'
    calls = []
    for path in root.rglob('*.py'):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not any(n.name in ('PostgresEventPublisher', 'OwnedOutboxPublisher', 'get_tenant_event_publisher', 'install_tenant_event_publisher') for n in node.names)
            if isinstance(node, ast.Call):
                assert not (isinstance(node.func, ast.Attribute) and node.func.attr == 'publish')
                if isinstance(node.func, ast.Name) and node.func.id == 'publish_directory_event':
                    assert ast.unparse(node.args[0]) == 'session'
                    calls.append({k.arg: ast.unparse(k.value) for k in node.keywords})
    assert {c['event_type']: c['operation_id'] for c in calls} == {
        'USER_CREATED_V1': 'u.id', 'GROUP_MEMBER_ADDED_V1': 'm.id',
        'GROUP_MEMBER_REMOVED_V1': 'membership_id',
    }
