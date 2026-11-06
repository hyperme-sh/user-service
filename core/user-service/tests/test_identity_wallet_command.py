"""The identity command is awaitable and returns a binding, not a context manager."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import pytest
from user_service.identity_wallet_bind import upsert_wallet_binding

@pytest.mark.asyncio
async def test_wallet_command_returns_binding():
    session = SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: None)),
        add=Mock(), flush=AsyncMock(), refresh=AsyncMock())
    result = await upsert_wallet_binding(session, keycloak_sub='verified-subject',
        email='fixture@example.test', wallet_address='0x0000000000000000000000000000000000000001')
    assert result.keycloak_sub == 'verified-subject'
    assert result.wallet_address == '0x0000000000000000000000000000000000000001'
    session.flush.assert_awaited_once()
