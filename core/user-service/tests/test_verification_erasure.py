import httpx
import pytest
from user_service import verification_erasure as owner
from user_service.closure_clients import OwnerUnavailable

@pytest.mark.asyncio
async def test_unconfigured_owner_no_network(monkeypatch):
    monkeypatch.delenv('ACCOUNT_CLOSURE_VERIFICATION_ENABLED',raising=False)
    monkeypatch.delenv('ACCOUNT_CLOSURE_VERIFICATION_URL',raising=False)
    assert await owner.erase_verification('subject')=={'not_configured':True}

@pytest.mark.asyncio
@pytest.mark.parametrize('reply,success', [({'status':'erased'},True),({},False),({'status':'queued'},False)])
async def test_requires_completed_owner_receipt(monkeypatch,reply,success):
    monkeypatch.setenv('ACCOUNT_CLOSURE_VERIFICATION_ENABLED','true')
    monkeypatch.setenv('ACCOUNT_CLOSURE_VERIFICATION_URL','https://verification.test')
    monkeypatch.setattr(owner,'service_url',lambda _: 'https://verification.test')
    monkeypatch.setattr(owner,'service_secret',lambda _: 'test-token')
    def handle(request):
        assert request.headers['x-verification-admin-token']=='test-token'
        assert request.url.path=='/internal/verification/erase'
        return httpx.Response(200,json=reply)
    real=httpx.AsyncClient
    monkeypatch.setattr(owner.httpx,'AsyncClient',lambda **kw:real(transport=httpx.MockTransport(handle),**kw))
    if success:
        assert await owner.erase_verification('subject')=={'complete':True}
    else:
        with pytest.raises(OwnerUnavailable):
            await owner.erase_verification('subject')

@pytest.mark.asyncio
async def test_enabled_owner_missing_url_fails_closed(monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_VERIFICATION_ENABLED","true")
    monkeypatch.delenv("ACCOUNT_CLOSURE_VERIFICATION_URL",raising=False)
    with pytest.raises(OwnerUnavailable):
        await owner.erase_verification("subject")
