"""Inactive HTTP checks for a declared synthetic identity; no fixture provisioning."""
import asyncio
from dataclasses import dataclass
from datetime import datetime
import json
from urllib.parse import urlsplit
from uuid import UUID
import httpx


class Unavailable(ValueError):
    pass


@dataclass(frozen=True)
class Binding:
    subject: str
    tenant: UUID
    other_tenant: UUID
    member: UUID
    command: UUID
    wallet: str
    enabled: bool = False

    def __post_init__(self):
        if not isinstance(self.subject,str) or not self.subject.strip() or len(self.subject)>512:
            raise ValueError('Declared synthetic subject required')
        if any(type(value) is not UUID or not value.int for value in (self.tenant,self.other_tenant,self.member,self.command)) or self.tenant==self.other_tenant:
            raise ValueError('Distinct declared scopes and operation required')
        import re
        if not isinstance(self.wallet,str) or not re.fullmatch('0x[0-9a-fA-F]{40}',self.wallet):
            raise ValueError('Declared synthetic wallet required')


def endpoint(value):
    parsed=urlsplit(value)
    if (parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('','/')
            or (parsed.scheme=='http' and parsed.hostname not in ('127.0.0.1','::1'))):
        raise ValueError('Private HTTPS or isolated loopback owner required')
    return value.rstrip('/')


def credential(value):
    if not isinstance(value,str) or not 16<=len(value)<=4096 or any(ord(c)<33 or ord(c)>126 for c in value):
        raise ValueError('Dedicated owner credential required')
    return value


async def probe(binding, *, url, identity_token, reader_token, previous=None, transport=None):
    """Replay one original command, verify lookups and tenant refusals.

    The caller persists the original result privately for subsequent restart and
    rollback comparisons. No cleanup, enrollment or financial actions are added.
    """
    if binding.enabled is not True:
        raise Unavailable('User canary binding disabled')
    def qualify(value):
        if not isinstance(value,dict) or value.get('status')!='applied' or value.get('command_id')!=str(binding.command):
            raise Unavailable('Original wallet command unavailable')
        fact=value.get('binding')
        if not isinstance(fact,dict) or fact.get('keycloak_sub')!=binding.subject or str(fact.get('wallet_address','')).lower()!=binding.wallet.lower():
            raise Unavailable('Wallet identity differs')
        try:
            if datetime.fromisoformat(fact['bound_at']).utcoffset() is None:raise ValueError()
        except (KeyError,TypeError,ValueError):raise Unavailable('Original binding timestamp unavailable') from None
    if previous is not None:qualify(previous)
    url=endpoint(url)
    identity_token=credential(identity_token);reader_token=credential(reader_token)
    if identity_token==reader_token:raise ValueError('Reader and identity credentials must differ')
    async with asyncio.timeout(30):
        async with httpx.AsyncClient(timeout=5,trust_env=False,follow_redirects=False,transport=transport) as client:
            async def request(path,body,token,reader=False):
                header='X-Account-Lifecycle-Token' if reader else 'Authorization'
                value=token if reader else 'Bearer '+token
                async with client.stream('POST',url+'/api/v1/internal/'+path,json=body,
                                         headers={header:value,'Accept-Encoding':'identity'}) as response:
                    if response.status_code!=200 or response.headers.get('content-encoding','identity')!='identity':
                        raise Unavailable('User owner response unavailable')
                    raw=bytearray()
                    async for part in response.aiter_bytes():
                        raw.extend(part)
                        if len(raw)>65536:raise Unavailable('User owner response oversized')
                    try:return json.loads(raw)
                    except (ValueError,RecursionError):raise Unavailable('Invalid User owner response') from None
            member=await request('identity/session-member',{'subject':binding.subject,'tenant_id':str(binding.tenant)},identity_token)
            if member!={'user_id':str(binding.member)}:raise Unavailable('Declared member unavailable')
            other=await request('identity/session-member',{'subject':binding.subject,'tenant_id':str(binding.other_tenant)},identity_token)
            if other is not None:raise Unavailable('Undeclared tenant membership accepted')
            status=await request('account-lifecycle/check',{'subject':binding.subject,'tenant_id':str(binding.tenant)},reader_token,True)
            if not isinstance(status,dict) or set(status)!={'blocked'} or status['blocked'] is not False:raise Unavailable('Declared identity is not active')
            existing=await request('identity/get-wallet',{'subject':binding.subject},identity_token)
            if existing is not None and (not isinstance(existing,dict) or existing.get('keycloak_sub')!=binding.subject
                    or str(existing.get('wallet_address','')).lower()!=binding.wallet.lower()):
                raise Unavailable('Declared identity already has another wallet')
            payload=dict(command_id=str(binding.command),subject=binding.subject,wallet_address=binding.wallet)
            first=await request('identity/bind-wallet',payload,identity_token)
            qualify(first)
            if previous is not None:
                if previous!=first:raise Unavailable('Original committed command changed')
            if await request('identity/bind-wallet',payload,identity_token)!=first:
                raise Unavailable('Repeat command changed its result')
            wallet=await request('identity/get-wallet',{'subject':binding.subject},identity_token)
            if not isinstance(wallet,dict):raise Unavailable('Wallet lookup unavailable')
            try:
                same_time=datetime.fromisoformat(wallet['bound_at'])==datetime.fromisoformat(first['binding']['bound_at'])
            except (KeyError,TypeError,ValueError):same_time=False
            if not same_time or {k:v for k,v in wallet.items() if k!='bound_at'}!={k:v for k,v in first['binding'].items() if k!='bound_at'}:
                raise Unavailable('Wallet lookup differs from committed command')
            return first
