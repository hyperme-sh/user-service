"""Offline HTTP contract doubles; no owner process, database or shared fixture."""
import asyncio
from uuid import UUID
import httpx
import pytest
from user_service.canary import Binding, Unavailable, probe


def binding(enabled=True):
    return Binding('synthetic-canary',UUID(int=1),UUID(int=2),UUID(int=3),UUID(int=4),'0x'+'11'*20,enabled)


def run(handler, **kw):
    return asyncio.run(probe(binding(),url='http://127.0.0.1:1234',identity_token='i'*32,reader_token='r'*32,
                             transport=httpx.MockTransport(handler),**kw))


def result():
    return {'status':'applied','command_id':str(UUID(int=4)),'binding':{'keycloak_sub':'synthetic-canary',
        'wallet_address':'0x'+'11'*20,'email':None,'bound_at':'2026-11-19 00:00:00+00:00'}}


def handler(request):
    import json
    path=request.url.path.rsplit('/',1)[-1];body=json.loads(request.content)
    if path=='bind-wallet':value=result()
    elif path=='get-wallet':
        value=result()['binding'];value['bound_at']=value['bound_at'].replace(' ','T')
    elif path=='session-member':value={'user_id':str(UUID(int=3))} if body['tenant_id']==str(UUID(int=1)) else None
    else:value={'blocked':False}
    return httpx.Response(200,content=__import__("json").dumps(value))


def test_original_command_replay_and_reader_contract():
    assert run(handler)==result()
    assert run(handler,previous=result())==result()


def test_disabled_before_network_or_credential_access():
    with pytest.raises(Unavailable):
        asyncio.run(probe(binding(False),url='',identity_token='',reader_token=''))


@pytest.mark.parametrize('failure',['redirect','wrong-command','changed-time','other-tenant','blocked','oversized','bad-json'])
def test_missing_or_changed_observations_refuse(failure):
    def changed(request):
        response=handler(request)
        if failure=='redirect':return httpx.Response(302,headers={'location':'https://untrusted.invalid'})
        if failure=='oversized':return httpx.Response(200,content=b' '*65537)
        if failure=='bad-json':return httpx.Response(200,content=b'{')
        value=response.json();path=request.url.path.rsplit('/',1)[-1]
        if path=='bind-wallet' and failure=='wrong-command':value['command_id']=str(UUID(int=9))
        if path=='bind-wallet' and failure=='changed-time':value['binding']['bound_at']='2026-11-18T00:00:00+00:00'
        if path=='session-member' and failure=='other-tenant':value={'user_id':str(UUID(int=3))}
        if path=='check' and failure=='blocked':value={'blocked':True}
        return httpx.Response(200,content=__import__("json").dumps(value))
    with pytest.raises(Unavailable):run(changed,previous=result())


def test_invalid_endpoint_and_shared_credentials_refuse():
    from user_service.canary import endpoint
    for url in ('http://remote.invalid','https://user:secret@owner.invalid','https://owner.invalid/?q=x'):
        with pytest.raises(ValueError):endpoint(url)
    with pytest.raises(ValueError):
        asyncio.run(probe(binding(),url='https://owner.invalid',identity_token='x'*32,reader_token='x'*32))


def test_failed_preflight_never_mutates_identity():
    calls=[]
    def denied(request):
        calls.append(request.url.path)
        if request.url.path.endswith('/check'):return httpx.Response(200,json={'blocked':True})
        return handler(request)
    with pytest.raises(Unavailable):run(denied)
    assert not any(path.endswith('/bind-wallet') for path in calls)


@pytest.mark.parametrize('blocked',[0,None,'false',[]])
def test_reader_requires_literal_boolean_false(blocked):
    def invalid(request):
        if request.url.path.endswith('/check'):return httpx.Response(200,json={'blocked':blocked})
        return handler(request)
    with pytest.raises(Unavailable):run(invalid)


@pytest.mark.parametrize('field,value',[('command_id',str(UUID(int=99))),('keycloak_sub','other'),('wallet_address','0x'+'22'*20)])
def test_changed_original_is_refused_before_any_http(field,value):
    original=result()
    (original if field=='command_id' else original['binding'])[field]=value
    calls=[]
    def observed(request):calls.append(request);return handler(request)
    with pytest.raises(Unavailable):run(observed,previous=original)
    assert not calls
