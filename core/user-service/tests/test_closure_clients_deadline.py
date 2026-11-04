"""A trickling peer must not retain a worker's claim indefinitely."""

import asyncio

import httpx
import pytest
from user_service import closure_clients


class SlowStream(httpx.AsyncByteStream):
    def __init__(self):
        self.closed = False

    async def __aiter__(self):
        for _ in range(1000):
            await asyncio.sleep(0.005)
            yield b" "

    async def aclose(self):
        self.closed = True


async def test_total_owner_deadline_closes_slow_stream_and_allows_next_call(
    monkeypatch,
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://owners.example")
    monkeypatch.setattr(
        closure_clients, "OWNER_RPC_DEADLINE_SECONDS", 0.03, raising=False
    )
    stream = SlowStream()

    async def respond(request):
        if request.url.path == "/slow":
            return httpx.Response(200, stream=stream)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        owners = closure_clients.ClosureOwners(client)
        with pytest.raises(
            closure_clients.OwnerUnavailable, match="^owner_unavailable$"
        ):
            await asyncio.wait_for(owners.call("KEYS", "/slow"), timeout=0.25)
        assert stream.closed
        assert await owners.call("KEYS", "/fast") == {"ok": True}
