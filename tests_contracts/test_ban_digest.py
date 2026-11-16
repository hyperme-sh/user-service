"""Owner hash and HTTP authorization contracts; isolated fake database."""
import sys
from pathlib import Path
from uuid import uuid4
from types import SimpleNamespace
from unittest.mock import AsyncMock
from contextlib import asynccontextmanager

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'core/user-service/src'))
from fastapi import FastAPI
import asyncio
import httpx
from user_service.ban_digest import router, fingerprint


def test_canonical_active_set_and_tenant_binding():
    tenant, other, subject = uuid4(), uuid4(), uuid4()
    rows = [('user', subject), ('device', uuid4())]
    assert fingerprint(tenant, rows) == fingerprint(tenant, list(reversed(rows))+rows)
    assert fingerprint(tenant, rows) != fingerprint(other, rows)
    assert fingerprint(tenant, rows) != fingerprint(tenant, rows[:1])
    assert fingerprint(tenant, []) == fingerprint(tenant, [])


def test_authorization_fresh_reads_and_exact_fields(monkeypatch):
    tenant, other, subject = uuid4(), uuid4(), uuid4()
    monkeypatch.setenv('PLANE_SCOPE_AUTHORITY_TOKEN', 'plane-unit-secret')
    monkeypatch.setenv('AUTH_SCOPE_AUTHORITY_TOKEN', 'auth-unit-secret')
    monkeypatch.setenv('PLANE_STATUS_TENANT_IDS', '["'+str(tenant)+'"]')
    rows = [('user', subject)]
    db = SimpleNamespace(execute=AsyncMock())
    db.execute.side_effect = lambda *a, **k: SimpleNamespace(all=lambda:list(rows))
    @asynccontextmanager
    async def unit(): yield db
    db.begin = unit
    app = FastAPI()
    app.state.session_maker = unit
    app.include_router(router)
    async def check():
      async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url='http://unit') as client:
        async def read(token='plane-unit-secret', tid=tenant):
            return await client.post('/internal/operator-bans/digest', json={'tenant_id':str(tid)}, headers={'Authorization':'Bearer '+token})
        assert (await read('')).status_code == 401
        assert (await read('auth-unit-secret')).status_code == 403
        assert (await read(tid=other)).status_code == 403
        assert db.execute.await_count == 0
        first=await read()
        assert first.status_code == 200
        assert set(first.json()) == {'ban_hash','computed_at'}
        assert first.headers['cache-control'] == 'no-store'
        assert str(subject) not in first.text
        rows.clear()
        assert (await read()).json()['ban_hash'] != first.json()['ban_hash']
        assert db.execute.await_count == 4
        db.execute.side_effect = RuntimeError('storage unavailable')
        assert (await read()).status_code == 500
        monkeypatch.delenv('PLANE_STATUS_TENANT_IDS')
        assert (await read()).status_code == 403

    asyncio.run(check())
