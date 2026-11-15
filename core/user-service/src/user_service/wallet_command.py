"""Apply an Auth-owned binding command once within the User transaction."""
import hashlib
import json

from sqlalchemy import text
from user_service.identity_wallet_bind import upsert_wallet_binding


async def apply(session, *, command_id, subject, email, wallet_address):
    payload = dict(subject=subject, email=email, wallet_address=wallet_address)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    # Serialize duplicates before reading their committed outcome. Subject locking
    # also protects two different commands changing the same person's binding.
    for key in (f'wallet-command:{command_id}', f'wallet-subject:{subject}'):
        await session.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(:key,0))'), {'key': key})
    old = (await session.execute(text('SELECT payload_hash,result FROM user_wallet_commands WHERE id=:id'),
                                 {'id': command_id})).mappings().one_or_none()
    if old is not None:
        if old['payload_hash'] != digest:
            raise ValueError('Wallet command ID already has another payload')
        return response(old['result'], command_id, payload)
    # Save a definitive business rejection too: a delayed retry must not become
    # a different decision after the conflicting address is subsequently freed.
    from auth_service.siwe import SiweError
    try:
        async with session.begin_nested():
            binding = await upsert_wallet_binding(session, keycloak_sub=subject,
                                                 email=email, wallet_address=wallet_address)
        result = {'status': 'applied', 'bound_at': str(binding.bound_at)}
    except SiweError:
        result = {'status': 'rejected', 'detail': 'Wallet binding was rejected'}
    result = json.loads(json.dumps(result, default=str))
    await session.execute(text('INSERT INTO user_wallet_commands(id,payload_hash,result) VALUES(:id,:hash,CAST(:result AS jsonb))'),
                          {'id': command_id, 'hash': digest, 'result': json.dumps(result)})
    return response(result, command_id, payload)


def response(result, command_id, payload):
    value = dict(result, command_id=str(command_id))
    if value['status'] == 'applied':
        from auth_service.siwe import checksum_address
        value['binding'] = dict(keycloak_sub=payload['subject'], email=payload['email'],
                                wallet_address=checksum_address(payload['wallet_address']),
                                bound_at=value.pop('bound_at'))
    return value
