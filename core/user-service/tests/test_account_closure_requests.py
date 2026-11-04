"""Real PostgreSQL intake, authorization, provenance and retry coverage."""
from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt
from user_service.account_closure import record_request

SUB = "11111111-1111-1111-1111-111111111111"
CONFIRM = {"confirmation": "CLOSE MY ACCOUNT"}


@pytest.fixture(autouse=True)
def intake(monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_REQUESTS_ENABLED", "true")




@pytest.fixture(autouse=True)
def clean_requests(closure_sync_url):
    migrated_sync_url = closure_sync_url
    engine = create_engine(migrated_sync_url)
    with engine.begin() as cx:
        cx.execute(text("DELETE FROM account_closure_requests"))
    yield
    engine.dispose()


async def test_confirmation_and_default_off(http_client, tenant_headers, monkeypatch):
    path = "/api/v1/me/account-closure-request"
    for body in ({}, {"confirmation": "close"}, {**CONFIRM, "subject": "someone-else"}):
        result = await http_client.post(path, headers=tenant_headers, json=body)
        assert result.status_code == 422
    monkeypatch.delenv("ACCOUNT_CLOSURE_REQUESTS_ENABLED")
    result = await http_client.post(path, headers=tenant_headers, json=CONFIRM)
    assert result.status_code == 503
    assert (await http_client.get(path, headers=tenant_headers)).status_code == 404


async def test_self_request_is_pending_and_retry_preserves_provenance(http_client, tenant_headers, migrated_sync_url, seed):
    path = "/api/v1/me/account-closure-request"
    first = await http_client.post(path, headers=tenant_headers, json=CONFIRM)
    assert first.status_code == 202, first.text
    data = first.json()
    assert first.headers['Cache-Control'] == 'no-store'
    assert data['state'] == 'pending'
    assert data['source'] == 'self_service'
    assert data['subject'] == SUB
    assert 'closed_at' not in data and 'delete_after' not in data
    assert (await http_client.post(path, headers=tenant_headers, json=CONFIRM)).json() == data
    assert (await http_client.get(path, headers=tenant_headers)).json() == data
    engine = create_engine(migrated_sync_url)
    with engine.connect() as cx:
        assert cx.execute(text("SELECT requested_by FROM account_closure_requests WHERE tenant_id=:t"), {'t':seed.ta}).scalar_one() == SUB
        # Intake must not masquerade as identity closure or stop active workloads.
        assert cx.execute(text("SELECT is_active FROM users WHERE tenant_id=:t AND keycloak_sub=:s"), {'t':seed.ta, 's':SUB}).scalar_one() is True
    engine.dispose()


async def test_tenant_header_must_match_token(http_client, tenant_headers, seed):
    result = await http_client.post('/api/v1/me/account-closure-request',
        headers={**tenant_headers, 'X-Tenant-ID': str(seed.tb)}, json=CONFIRM)
    assert result.status_code == 403


async def test_subject_does_not_fall_back_to_email(http_client, tenant_headers, app, auth_context, seed):
    assert (await http_client.post('/api/v1/me/account-closure-request', headers=tenant_headers, json=CONFIRM)).status_code == 202
    from auth_service.deps import get_current_user
    from auth_service.schemas import AuthMeResponse
    async def other():
        return AuthMeResponse(sub='unbound-subject', email='actor@example.com', tenant_id=seed.ta, roles=[], scopes=[])
    app.dependency_overrides[get_current_user] = other
    result = await http_client.post('/api/v1/me/account-closure-request', headers=tenant_headers, json=CONFIRM)
    assert result.status_code == 404
    assert (await http_client.get('/api/v1/me/account-closure-request', headers=tenant_headers)).status_code == 404


def operator_headers(tenant, perms):
    token = mint_tenant_session_jwt(claims={'sub':'support-1', 'permissions':perms}, tenant_id=tenant)
    return {'Authorization':f'Bearer {token}', 'X-Tenant-ID':str(tenant)}


async def test_operator_intake_and_status_require_support(http_client, seed, monkeypatch):
    from api.core import config
    monkeypatch.setattr(config.settings, 'api_key_exchange_jwt_secret', 'test-api-key-exchange-secret-min-32-chars!!')
    path = '/api/v1/operator/account-closure-requests'
    denied = operator_headers(seed.ta, ['operator:console'])
    assert (await http_client.post(path, headers=denied, json={**CONFIRM, 'subject':SUB})).status_code == 403
    assert (await http_client.get(path, headers=denied, params={'subject':SUB})).status_code == 403
    allowed = operator_headers(seed.ta, ['operator:console','operator:support'])
    result = await http_client.post(path, headers=allowed, json={**CONFIRM,'subject':SUB})
    assert result.status_code == 202, result.text
    assert result.json()['source'] == 'operator'
    assert (await http_client.get(path, headers=allowed, params={'subject':SUB})).json() == result.json()
    other_tenant = operator_headers(seed.tb, ['operator:console','operator:support'])
    assert (await http_client.get(path, headers=other_tenant, params={'subject':SUB})).status_code == 404
    # Self-service retry preserves the operator request's original provenance.
    self_retry = await http_client.post('/api/v1/me/account-closure-request',
        headers={'Authorization':'Bearer test-token','X-Tenant-ID':str(seed.ta)}, json=CONFIRM)
    assert self_retry.json() == result.json()


async def test_concurrent_requests_have_one_timestamp_and_actor(migrated_sync_url, seed):
    url = migrated_sync_url.replace('postgresql+psycopg://','postgresql+asyncpg://')
    engine = create_async_engine(url)
    maker = async_sessionmaker(engine)
    async def submit(actor, source):
        async with maker.begin() as session:
            return await record_request(session, seed.ta, SUB, actor, source)
    try:
        results = await asyncio.gather(submit(SUB,'self_service'), submit('support-1','operator'))
        assert results[0] == results[1]
    finally:
        await engine.dispose()


def test_rls_blocks_cross_tenant_reads_and_writes(migrated_sync_url, seed):
    engine = create_engine(migrated_sync_url)
    try:
        with engine.begin() as cx:
            cx.execute(text("INSERT INTO account_closure_requests VALUES (:t, :s, now(), :s, 'self_service')"), {'t':seed.ta,'s':SUB})
            cx.execute(text("CREATE ROLE closure_request_rls NOBYPASSRLS"))
            cx.execute(text("GRANT SELECT, INSERT ON account_closure_requests TO closure_request_rls"))
        with engine.begin() as cx:
            cx.execute(text("SET LOCAL ROLE closure_request_rls"))
            assert cx.execute(text("SELECT count(*) FROM account_closure_requests")).scalar_one() == 0
            cx.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {'t':str(seed.tb)})
            assert cx.execute(text("SELECT count(*) FROM account_closure_requests")).scalar_one() == 0
            with pytest.raises(Exception, match='row-level security'):
                with cx.begin_nested():
                    cx.execute(text("INSERT INTO account_closure_requests VALUES (:t, 'forged', now(), 'forged', 'self_service')"), {'t':seed.ta})
            cx.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {'t':str(seed.ta)})
            assert cx.execute(text("SELECT subject FROM account_closure_requests")).scalar_one() == SUB
    finally:
        with engine.begin() as cx:
            cx.execute(text("DROP OWNED BY closure_request_rls"))
            cx.execute(text("DROP ROLE closure_request_rls"))
        engine.dispose()
