"""Wallet command retries preserve a single owner mutation."""
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
import json
import pytest
from auth_service.siwe import SiweError
from user_service import wallet_command


class Session:
    def __init__(self):
        self.rows = {}
    @asynccontextmanager
    async def begin_nested(self):
        yield
    async def execute(self, sql, values):
        sql = str(sql)
        row = None
        if sql.startswith('SELECT payload_hash'):
            row = self.rows.get(values['id'])
        elif sql.startswith('INSERT'):
            self.rows[values['id']] = dict(payload_hash=values['hash'], result=json.loads(values['result']))
        return SimpleNamespace(mappings=lambda: SimpleNamespace(one_or_none=lambda: row))


@pytest.mark.asyncio
async def test_duplicate_delivery_and_conflicting_payload(monkeypatch):
    db = Session()
    bind = AsyncMock(return_value=SimpleNamespace(bound_at=datetime.now(UTC)))
    monkeypatch.setattr(wallet_command, 'upsert_wallet_binding', bind)
    args = dict(command_id=uuid.uuid4(), subject='subject', email='test@example.test', wallet_address='0x'+'11'*20)
    first = await wallet_command.apply(db, **args)
    assert await wallet_command.apply(db, **args) == first
    bind.assert_awaited_once()
    with pytest.raises(ValueError, match='another payload'):
        await wallet_command.apply(db, **(args | {'subject':'other'}))
    saved = json.dumps(list(db.rows.values()))
    assert 'test@example.test' not in saved and args['wallet_address'] not in saved


@pytest.mark.asyncio
async def test_rejected_command_remains_rejected(monkeypatch):
    db = Session()
    bind = AsyncMock(side_effect=SiweError('taken'))
    monkeypatch.setattr(wallet_command, 'upsert_wallet_binding', bind)
    args = dict(command_id=uuid.uuid4(), subject='subject', email=None, wallet_address='0x'+'11'*20)
    assert (await wallet_command.apply(db, **args))['status'] == 'rejected'
    bind.side_effect = None
    assert (await wallet_command.apply(db, **args))['status'] == 'rejected'
    bind.assert_awaited_once()


@pytest.mark.asyncio
async def test_postgres_concurrent_delivery_and_rollback(authority, monkeypatch):
    import asyncio
    from sqlalchemy import text
    from user_service.wallet_command_schema import install
    install(authority.sync)
    install(authority.sync)
    args = dict(command_id=uuid.uuid4(), subject='concurrent', email=None, wallet_address='0x'+'22'*20)
    async def deliver():
        async with authority.maker() as db, db.begin():
            return await wallet_command.apply(db, **args)
    outcomes = await asyncio.gather(deliver(), deliver())
    assert outcomes[0] == outcomes[1]
    async with authority.maker() as db:
        assert await db.scalar(text("SELECT count(*) FROM user_wallet_bindings WHERE keycloak_sub='concurrent'")) == 1
    other = args | {'command_id': uuid.uuid4(), 'subject': 'rollback', 'wallet_address': '0x'+'33'*20}
    with pytest.raises(RuntimeError):
        async with authority.maker() as db, db.begin():
            await wallet_command.apply(db, **other)
            raise RuntimeError('rollback')
    async with authority.maker() as db:
        assert await db.scalar(text('SELECT count(*) FROM user_wallet_commands WHERE id=:id'), {'id':other['command_id']}) == 0
        assert await db.scalar(text("SELECT count(*) FROM user_wallet_bindings WHERE keycloak_sub='rollback'")) == 0


from test_scoped_authority import authority


def test_command_id_cannot_be_sent_to_unrelated_operations():
    from user_service.identity_api import Command
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Command(command_id='not-a-uuid')


@pytest.mark.asyncio
@pytest.mark.parametrize('table,version', [(None,0),('user_wallet_commands',1)])
async def test_capability_is_advertised_only_after_schema_installation(table,version):
    from user_service.identity_api import wallet_command_contract
    @asynccontextmanager
    async def session():
        yield SimpleNamespace(scalar=AsyncMock(return_value=table))
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(session_maker=session)))
    assert await wallet_command_contract(request)=={'wallet_command_version':version}
