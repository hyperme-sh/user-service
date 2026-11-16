"""Mock-only private reader contracts; no database or provider calls."""
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from user_service import account_status_reader as reader


def connection(role=('account_status_reader', 'user_owner', 'on', False, False), scalars=None):
    result = Mock()
    result.one.return_value = role
    return Mock(execute=AsyncMock(return_value=result),
                scalar=AsyncMock(side_effect=scalars if scalars is not None else [False, False, False, True, True]))


async def test_reader_accepts_only_explicit_read_role():
    await reader.qualify(connection(), 'account_status_reader', 'user_owner')
    for role in [('other', 'user_owner', 'on', False, False),
                 ('account_status_reader', 'public', 'on', False, False),
                 ('account_status_reader', 'user_owner', 'off', False, False),
                 ('account_status_reader', 'user_owner', 'on', True, False),
                 ('account_status_reader', 'user_owner', 'on', False, True)]:
        with pytest.raises(RuntimeError):
            await reader.qualify(connection(role), 'account_status_reader', 'user_owner')
    for index in range(5):
        values = [False, False, False, True, True]
        values[index] = not values[index]
        with pytest.raises(RuntimeError):
            await reader.qualify(connection(scalars=values), 'account_status_reader', 'user_owner')


async def test_default_off_never_opens_database(monkeypatch):
    monkeypatch.delenv('ACCOUNT_STATUS_READER_ENABLED', raising=False)
    factory = Mock()
    monkeypatch.setattr(reader, 'create_async_engine', factory)
    app = reader.create_app()
    with pytest.raises(RuntimeError, match='disabled'):
        async with app.router.lifespan_context(app):
            pass
    factory.assert_not_called()


async def test_failed_startup_disposes_and_hides_details(monkeypatch):
    monkeypatch.setenv('ACCOUNT_STATUS_READER_ENABLED', 'true')
    monkeypatch.setenv('ACCOUNT_STATUS_DATABASE_URL', 'postgresql://reader:private@localhost/db')
    monkeypatch.setenv('ACCOUNT_STATUS_DATABASE_ROLE', 'account_status_reader')
    monkeypatch.setenv('ACCOUNT_STATUS_DATABASE_SCHEMA', 'user_owner')
    @asynccontextmanager
    async def begin():
        raise RuntimeError('private database material')
        yield
    engine = Mock(begin=begin, dispose=AsyncMock())
    monkeypatch.setattr(reader, 'create_async_engine', Mock(return_value=engine))
    app = reader.create_app()
    with pytest.raises(RuntimeError, match='^Account-status reader unavailable$'):
        async with app.router.lifespan_context(app):
            pass
    engine.dispose.assert_awaited_once()


def test_private_routes_keep_owner_auth_and_exclude_mutations():
    app = reader.create_app()
    routes = {r.path: r for r in app.routes}
    assert len(routes) == 2
    status = next(route for path, route in routes.items() if path.endswith('/check'))
    assert status.endpoint is reader.check
    assert all(any(d.call is reader.require_reader for d in route.dependant.dependencies)
               for route in routes.values())
    # Remove only the DB middleware: this unit isolates the actual auth dependency.
    app.user_middleware = []
    def denied():
        raise HTTPException(403, 'refused')
    app.dependency_overrides[reader.require_reader] = denied
    client = TestClient(app)
    for method, path in [('post', status.path), ('get', '/internal/ready')]:
        response = getattr(client, method)(path, **({'json': {'subject': 'fixture'}} if method == 'post' else {}))
        assert response.status_code == 403


def test_native_reader_auth_rejects_wrong_caller(monkeypatch):
    from fastapi import Response
    from starlette.requests import Request
    from user_service import closure_contracts
    monkeypatch.setattr(closure_contracts, 'authorized_call', lambda headers: False)
    with pytest.raises(HTTPException) as refused:
        reader.require_reader(Request({'type': 'http', 'headers': []}), Response())
    assert refused.value.status_code == 403
