import importlib.util
from importlib.metadata import requires
from unittest.mock import AsyncMock
from uuid import uuid4
import pytest
from operator_ban_store import active_ban, subject_banned_sync

def test_runtime_dependency_boundary():
    assert all(d.lower().startswith('sqlalchemy') for d in requires('operator-ban-store'))
    for name in ('api', 'user_service', 'hypermesh_service'):
        assert importlib.util.find_spec(name) is None

@pytest.mark.asyncio
async def test_empty_subjects_do_not_query():
    session = AsyncMock()
    assert await active_ban(session, uuid4()) is False
    session.scalar.assert_not_called()

@pytest.mark.asyncio
async def test_database_errors_propagate():
    session = AsyncMock()
    session.scalar.side_effect = RuntimeError('database unavailable')
    with pytest.raises(RuntimeError, match='database unavailable'):
        await active_ban(session, uuid4(), users=[uuid4()])
    class BrokenConnection:
        def execute(self, statement):
            raise RuntimeError('database unavailable')
    with pytest.raises(RuntimeError, match='database unavailable'):
        subject_banned_sync(BrokenConnection(), uuid4(), 'user', uuid4())
