"""An unhealthy key owner cannot hold retirement checks open or grow their body."""
import asyncio
import uuid

import httpx
import pytest

from user_service import lifecycle_read


class Body(httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0):
        self.chunks = chunks
        self.delay = delay
        self.closed = False
        self.sent = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            self.sent += 1
            yield chunk

    async def aclose(self):
        self.closed = True


async def check(monkeypatch, body, status=200, request_delay=0):
    async def handle(request):
        await asyncio.sleep(request_delay)
        return httpx.Response(status, stream=body)

    original = httpx.AsyncClient
    monkeypatch.setattr(lifecycle_read.httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(handle), **kw))
    monkeypatch.setattr(lifecycle_read, "service_url", lambda _: "http://keys.test")
    monkeypatch.setattr(lifecycle_read, "service_secret", lambda _: "test-only")
    principal = lifecycle_read.Principal(subject=f"apikey:{uuid.uuid4()}", tenant_id=uuid.uuid4())
    return await asyncio.wait_for(lifecycle_read.key_blocked(principal), timeout=1)


@pytest.mark.asyncio
async def test_slow_trickle_has_total_deadline_and_closes_response(monkeypatch):
    monkeypatch.setattr(lifecycle_read, "KEY_STATUS_DEADLINE_SECONDS", 0.03)
    body = Body([b" "] * 100 + [b'{"blocked":false}'], delay=0.01)
    assert await check(monkeypatch, body) is True
    assert body.sent < 100
    assert body.closed


@pytest.mark.asyncio
async def test_deadline_also_bounds_request_before_response(monkeypatch):
    monkeypatch.setattr(lifecycle_read, "KEY_STATUS_DEADLINE_SECONDS", 0.03)
    assert await check(monkeypatch, Body([b'{"blocked":false}']), request_delay=2) is True


@pytest.mark.asyncio
async def test_oversized_reply_fails_closed_before_entire_body(monkeypatch):
    body = Body([b'{"blocked":false}'] + [b" " * 4096] * 32)
    assert await check(monkeypatch, body) is True
    assert body.sent < len(body.chunks)
    assert body.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("payload,expected", [(b'{"blocked":false}', False), (b'{"blocked":true}', True), (b'{"blocked":"false"}', True), (b'garbage', True)])
async def test_small_replies_preserve_fail_closed_semantics(monkeypatch, payload, expected):
    body = Body([payload])
    assert await check(monkeypatch, body) is expected
    assert body.closed
