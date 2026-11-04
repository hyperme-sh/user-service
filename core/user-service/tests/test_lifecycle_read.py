"""Retirement authority is realm-wide; mutation timestamps/scopes need proof."""

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from controlplane_identity.account_lifecycle import require_open_account
from jwt import InvalidTokenError
from sqlalchemy import create_engine, text


@pytest.fixture
def authority(monkeypatch):
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    return {"X-Account-Lifecycle-Token": "r" * 32}


async def test_global_tombstone_and_read_mutation_credential_separation(
    http_client, closure_sync_url, authority, seed
):
    subject = str(uuid.uuid4())
    path = "/api/v1/internal/account-lifecycle/check"
    assert (await http_client.post(path, json={"subject": subject})).status_code == 403
    assert (
        await http_client.post(
            path,
            headers={"X-Account-Lifecycle-Token": "w" * 32},
            json={"subject": subject},
        )
    ).status_code == 403
    assert (
        await http_client.post(path, headers=authority, json={"subject": subject})
    ).json() == {"blocked": False}
    eng = create_engine(closure_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("""INSERT INTO account_lifecycles
          (subject, requested_at, requested_by, source, state, retry_at, financial_hold, effects)
          VALUES (:s, now(), :s, 'self_service', 'closing', now(), false, '{}')"""),
            {"s": subject},
        )
    try:
        # No tenant header and a different membership both see the same denial.
        for headers in (authority, {**authority, "X-Tenant-ID": str(seed.tb)}):
            result = await http_client.post(
                path, headers=headers, json={"subject": subject}
            )
            assert result.json() == {"blocked": True}
            assert result.headers["Cache-Control"] == "no-store"
    finally:
        with eng.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
        eng.dispose()


async def test_permit_rejects_pending_wrong_time_and_unrecorded_scope(
    http_client, closure_sync_url, authority, seed
):
    subject = str(uuid.uuid4())
    actual = datetime(2026, 1, 1, tzinfo=UTC)
    path = "/api/v1/internal/account-lifecycle/permit"

    async def permit(**extras):
        return (
            await http_client.post(
                path,
                headers=authority,
                json={"subject": subject, "closed_at": actual.isoformat(), **extras},
            )
        ).json()["allowed"]

    eng = create_engine(closure_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("""INSERT INTO account_lifecycles
          (subject, requested_at, requested_by, source, state, retry_at, financial_hold, effects)
          VALUES (:s, now(), :s, 'self_service', 'closing', now(), false, '{}')"""),
            {"s": subject},
        )
    try:
        assert await permit() is False
        with eng.begin() as cx:
            cx.execute(
                text("UPDATE account_lifecycles SET closed_at=:at WHERE subject=:s"),
                {"at": actual, "s": subject},
            )
            cx.execute(
                text(
                    "INSERT INTO account_lifecycle_scopes VALUES (:t, :s, '[]', '{}')"
                ),
                {"t": seed.ta, "s": subject},
            )
        assert await permit() is True
        assert await permit(tenant_id=str(seed.ta)) is True
        assert await permit(tenant_id=str(seed.tb)) is False
        assert (
            await permit(closed_at=datetime(2026, 1, 2, tzinfo=UTC).isoformat())
            is False
        )
    finally:
        with eng.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycle_scopes WHERE subject=:s"),
                {"s": subject},
            )
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
        eng.dispose()


@pytest.mark.parametrize(
    "reply", [None, {}, {"blocked": True}, {"blocked": 0}, {"blocked": "false"}, []]
)
def test_signed_token_guard_fails_closed(authority, monkeypatch, respx_mock, reply):
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://users.example")
    route = respx_mock.post(
        "https://users.example/api/v1/internal/account-lifecycle/check"
    )
    route.mock(
        return_value=httpx.Response(503)
        if reply is None
        else httpx.Response(200, json=reply)
    )
    with pytest.raises(InvalidTokenError):
        require_open_account({"sub": "person", "tenant_id": str(uuid.uuid4())})


def test_signed_token_guard_open_only_on_explicit_boolean(
    authority, monkeypatch, respx_mock
):
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://users.example")
    respx_mock.post(
        "https://users.example/api/v1/internal/account-lifecycle/check"
    ).mock(return_value=httpx.Response(200, json={"blocked": False}))
    require_open_account({"sub": "person"})


async def test_membership_retirement_is_global_and_first_timestamp_is_immutable(
    closure_sync_url, authority, seed
):
    from datetime import timedelta

    from controlplane_tenancy.tenant_membership import (
        create_tenant_membership_row,
        retire_identity,
    )
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    subject = str(uuid.uuid4())
    actual = datetime.now(UTC)
    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    maker = async_sessionmaker(engine)
    try:
        async with maker.begin() as session:
            assert await retire_identity(session, subject, actual) == actual
        async with maker.begin() as session:
            assert (
                await retire_identity(session, subject, actual + timedelta(days=1))
                == actual
            )
        for tid in (seed.ta, seed.tb):
            async with maker.begin() as session:
                with pytest.raises(ValueError, match="retired"):
                    await create_tenant_membership_row(
                        session,
                        tid,
                        email=f"{subject}@example.invalid",
                        first_name="Person",
                        last_name="Closed",
                        keycloak_sub=subject,
                    )
    finally:
        await engine.dispose()


def test_gateway_offline_context_is_scoped_and_restored(
    authority, monkeypatch, respx_mock
):
    from controlplane_identity.account_lifecycle import offline_gateway_verification

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://users.example")
    route = respx_mock.post(
        "https://users.example/api/v1/internal/account-lifecycle/check"
    )
    route.mock(return_value=httpx.Response(503))
    with pytest.raises(RuntimeError, match="test exit"), offline_gateway_verification():
        require_open_account({"sub": "person"})
        raise RuntimeError("test exit")
    assert not route.called
    with pytest.raises(InvalidTokenError):
        require_open_account({"sub": "person"})
    assert route.called


def test_read_and_mutation_credentials_cannot_be_equal(authority, monkeypatch):
    from controlplane_identity.account_lifecycle import authorized_call

    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "r" * 32)
    assert authorized_call(authority) is False
    assert authorized_call(authority, mutation=True) is False


async def test_permit_rpc_propagates_tenant_to_rls_middleware(
    authority, monkeypatch, respx_mock
):
    from controlplane_identity.account_lifecycle import require_closure_permit

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://users.example")
    tid = uuid.uuid4()
    route = respx_mock.post(
        "https://users.example/api/v1/internal/account-lifecycle/permit"
    )
    route.mock(return_value=httpx.Response(200, json={"allowed": True}))
    await require_closure_permit(
        subject="person", closed_at=datetime.now(UTC), tenant_id=tid
    )
    assert route.calls.last.request.headers["X-Tenant-ID"] == str(tid)
    assert route.calls.last.request.headers["X-Account-Lifecycle-Token"] == "r" * 32


async def test_operator_guard_can_serve_on_its_own_event_loop(
    http_client, seed, authority, monkeypatch
):
    import asyncio
    import json

    from api.core import config
    from controlplane_identity.security.tenant_session_jwt import (
        mint_tenant_session_jwt,
    )

    monkeypatch.setattr(
        config.settings,
        "api_key_exchange_jwt_secret",
        "test-api-key-exchange-secret-min-32-chars!!",
    )
    monkeypatch.setenv("FASTAPI_ENV", "test")
    observed = []
    blocked = False

    async def guard(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = next(
                int(line.split(b":", 1)[1])
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            observed.append(json.loads(await reader.readexactly(length)))
            body = json.dumps({"blocked": blocked}).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(guard, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", f"http://127.0.0.1:{port}")
        token = mint_tenant_session_jwt(
            claims={"sub": "operator-identity", "permissions": ["operator:console"]},
            tenant_id=seed.ta,
        )
        headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(seed.ta)}
        response = await http_client.get("/api/v1/operator/session", headers=headers)
        assert response.status_code == 200, response.text
        assert observed[-1] == {
            "subject": "operator-identity",
            "tenant_id": str(seed.ta),
        }
        blocked = True
        assert (
            await http_client.get("/api/v1/operator/session", headers=headers)
        ).status_code == 403
    finally:
        server.close()
        await server.wait_closed()


async def test_scoped_permit_under_non_bypass_rls_role(
    http_client, closure_sync_url, authority, seed, monkeypatch
):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    subject = str(uuid.uuid4())
    role = "closure_reader_" + uuid.uuid4().hex
    actual = datetime.now(UTC)
    sync = create_engine(closure_sync_url)
    with sync.begin() as cx:
        cx.execute(text(f"CREATE ROLE {role} NOBYPASSRLS"))
        cx.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        cx.execute(
            text(
                f"GRANT SELECT ON account_lifecycles, account_lifecycle_scopes TO {role}"
            )
        )
        cx.execute(
            text("""INSERT INTO account_lifecycles
          (subject, requested_at, requested_by, source, state, closed_at, retry_at, financial_hold, effects)
          VALUES (:s, now(), :s, 'self_service', 'closing', :at, now(), false, '{}')"""),
            {"s": subject, "at": actual},
        )
        cx.execute(
            text("INSERT INTO account_lifecycle_scopes VALUES (:t,:s,'[]','{}')"),
            {"t": seed.ta, "s": subject},
        )
    restricted = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://"),
        connect_args={"server_settings": {"role": role}},
    )
    try:
        maker = async_sessionmaker(restricted)
        monkeypatch.setattr("user_service.middleware.get_session_maker", lambda: maker)
        path = "/api/v1/internal/account-lifecycle/permit"
        body = {
            "subject": subject,
            "closed_at": actual.isoformat(),
            "tenant_id": str(seed.ta),
        }
        assert (await http_client.post(path, headers=authority, json=body)).json() == {
            "allowed": False
        }
        assert (
            await http_client.post(
                path, headers={**authority, "X-Tenant-ID": str(seed.ta)}, json=body
            )
        ).json() == {"allowed": True}
        assert (
            await http_client.post(
                path, headers={**authority, "X-Tenant-ID": str(seed.tb)}, json=body
            )
        ).json() == {"allowed": False}
    finally:
        await restricted.dispose()
        with sync.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycle_scopes WHERE subject=:s"),
                {"s": subject},
            )
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
            cx.execute(text(f"DROP OWNED BY {role}"))
            cx.execute(text(f"DROP ROLE {role}"))
        sync.dispose()


async def test_denial_export_requires_complete_owner_receipts_and_projects_only_digests(
    http_client, closure_sync_url, authority, seed
):
    import json

    from controlplane_identity.account_lifecycle import key_digest, subject_digest

    subject = str(uuid.uuid4())
    key, lease = uuid.uuid4(), uuid.uuid4()
    engine = create_engine(closure_sync_url)
    headers = {**authority, "X-Tenant-ID": str(seed.ta)}
    path = "/api/v1/internal/account-lifecycle/denials"
    with engine.begin() as cx:
        cx.execute(
            text("""INSERT INTO account_lifecycles
          (subject, requested_at, requested_by, source, state, retry_at, financial_hold, effects)
          VALUES (:s, now(), :s, 'self_service', 'closing', now(), false, '{}')"""),
            {"s": subject},
        )
    try:
        assert (await http_client.get(path, headers=headers)).status_code == 503
        with engine.begin() as cx:
            cx.execute(
                text(
                    "UPDATE account_lifecycles SET effects=CAST(:effects AS jsonb) WHERE subject=:s"
                ),
                {"s": subject, "effects": json.dumps({"scope_discovery": True})},
            )
            cx.execute(
                text("INSERT INTO account_lifecycle_scopes VALUES (:t,:s,'[]','{}')"),
                {"t": seed.ta, "s": subject},
            )
        assert (await http_client.get(path, headers=headers)).status_code == 503
        receipt = {
            "api_keys": {"keys": [{"id": str(key), "fingerprint": "f" * 64}]},
            "hypermesh": {"lease_ids": [str(lease)]},
        }
        with engine.begin() as cx:
            cx.execute(
                text(
                    "UPDATE account_lifecycle_scopes SET effects=CAST(:effects AS jsonb) WHERE tenant_id=:t AND subject=:s"
                ),
                {"effects": json.dumps(receipt), "t": seed.ta, "s": subject},
            )
        result = await http_client.get(path, headers=headers)
        assert result.status_code == 200, result.text
        assert result.json() == {
            "version": 1,
            "complete": True,
            "subjects": [subject_digest(seed.ta, subject)],
            "keys": [key_digest(seed.ta, key)],
            "fingerprints": ["f" * 64],
            "leases": [str(lease)],
        }
        assert subject not in result.text and str(key) not in result.text
        other = await http_client.get(
            path, headers={**authority, "X-Tenant-ID": str(seed.tb)}
        )
        assert other.json()["subjects"] == [subject_digest(seed.tb, subject)]
        assert other.json()["keys"] == [] and other.json()["leases"] == []
    finally:
        with engine.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycle_scopes WHERE subject=:s"),
                {"s": subject},
            )
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
        engine.dispose()


@pytest.mark.parametrize("alias_conflict", [False, True])
async def test_scope_receipt_binds_inventory_and_erasure_to_completed_closure(
    http_client, closure_sync_url, authority, seed, alias_conflict
):
    import json
    from datetime import timedelta

    subject = str(uuid.uuid4())
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    closed = datetime.now(UTC) - timedelta(days=90)
    engine = create_engine(closure_sync_url)
    keys = {"keys": [{"id": str(key_id), "fingerprint": "a" * 64, "purpose": "renter"}]}
    with engine.begin() as cx:
        if alias_conflict:
            cx.execute(
                text("""INSERT INTO users
                (id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active)
                VALUES (:id,:t,:s,:email,'Another','Person','unspecified',true)"""),
                {
                    "id": uuid.UUID(subject),
                    "t": seed.ta,
                    "s": "other-" + subject,
                    "email": subject + "@example.invalid",
                },
            )
        cx.execute(
            text("INSERT INTO identity_retirements VALUES (:s,:at)"),
            {"s": subject, "at": closed},
        )
        cx.execute(
            text("""INSERT INTO account_lifecycles
            (subject,requested_at,requested_by,source,state,closed_at,retry_at,financial_hold,effects)
            VALUES (:s,:at,:s,'self_service','closing',:at,now(),false,cast(:root_effects as jsonb))"""),
            {
                "s": subject,
                "at": closed,
                "root_effects": json.dumps({"scope_discovery": True}),
            },
        )
        cx.execute(
            text(
                "INSERT INTO account_lifecycle_scopes VALUES (:t,:s,cast(:users as jsonb),cast(:effects as jsonb))"
            ),
            {
                "t": seed.ta,
                "s": subject,
                "users": json.dumps([str(user_id)]),
                "effects": json.dumps(
                    {"api_keys": keys, "profile_inventory_complete": True}
                ),
            },
        )

    async def fetch(tid=seed.ta, headers=None, at=closed):
        return (
            await http_client.post(
                "/api/v1/internal/account-lifecycle/scope",
                headers=headers or {**authority, "X-Tenant-ID": str(tid)},
                json={
                    "subject": subject,
                    "tenant_id": str(tid),
                    "closed_at": at.isoformat(),
                },
            )
        ).json()

    try:
        receipt = await fetch()
        assert receipt == {
            "allowed": True,
            "user_ids": [str(user_id)],
            "renter_ids": [str(user_id)] if alias_conflict else [str(user_id), subject],
            "renter_alias_ambiguous": alias_conflict,
            "keys": keys["keys"],
            "keys_complete": True,
            "erasure_allowed": False,
        }
        assert await fetch(headers={**authority, "X-Tenant-ID": str(seed.tb)}) == {
            "allowed": False
        }
        assert await fetch(seed.tb) == {"allowed": False}
        assert await fetch(at=closed + timedelta(seconds=1)) == {"allowed": False}
        with engine.begin() as cx:
            cx.execute(
                text("UPDATE account_lifecycles SET state='closed' WHERE subject=:s"),
                {"s": subject},
            )
        assert (await fetch())["erasure_allowed"] is (not alias_conflict)
        with engine.begin() as cx:
            cx.execute(
                text("UPDATE account_lifecycles SET closed_at=now() WHERE subject=:s"),
                {"s": subject},
            )
            recent = cx.scalar(
                text("SELECT closed_at FROM account_lifecycles WHERE subject=:s"),
                {"s": subject},
            )
        assert (await fetch(at=recent))["erasure_allowed"] is False
    finally:
        with engine.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycle_scopes WHERE subject=:s"),
                {"s": subject},
            )
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
            cx.execute(
                text("DELETE FROM identity_retirements WHERE subject=:s"),
                {"s": subject},
            )
            if alias_conflict:
                cx.execute(
                    text("DELETE FROM users WHERE id=:id"), {"id": uuid.UUID(subject)}
                )
        engine.dispose()


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {
            "allowed": True,
            "user_ids": [],
            "keys": [],
            "keys_complete": 1,
            "erasure_allowed": True,
        },
        {
            "allowed": True,
            "user_ids": ["not-uuid"],
            "keys": [],
            "keys_complete": True,
            "erasure_allowed": True,
        },
        {
            "allowed": True,
            "user_ids": [],
            "keys": [{"id": str(uuid.uuid4()), "fingerprint": "invalid"}],
            "keys_complete": True,
            "erasure_allowed": True,
        },
    ],
)
async def test_owner_scope_rpc_rejects_malformed_authority(
    authority, monkeypatch, respx_mock, bad
):
    from controlplane_identity.account_lifecycle import closure_scope

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://users.example")
    if isinstance(bad, dict) and bad.get("allowed") is True:
        bad = {"renter_ids": [], "renter_alias_ambiguous": False, **bad}
    respx_mock.post(
        "https://users.example/api/v1/internal/account-lifecycle/scope"
    ).mock(
        return_value=httpx.Response(503)
        if bad is None
        else httpx.Response(200, json=bad)
    )
    with pytest.raises(RuntimeError, match="scope unavailable"):
        await closure_scope(
            subject="person", closed_at=datetime.now(UTC), tenant_id=uuid.uuid4()
        )


async def test_owner_scope_rpc_carries_matching_tenant_and_canonical_receipt(
    authority, monkeypatch, respx_mock
):
    from controlplane_identity.account_lifecycle import closure_scope

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", "https://users.example")
    tid, person, key = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    reply = {
        "allowed": True,
        "user_ids": [str(person)],
        "renter_ids": [str(person)],
        "renter_alias_ambiguous": False,
        "keys": [{"id": str(key), "fingerprint": "a" * 64}],
        "keys_complete": True,
        "erasure_allowed": False,
    }
    route = respx_mock.post(
        "https://users.example/api/v1/internal/account-lifecycle/scope"
    ).mock(return_value=httpx.Response(200, json=reply))
    assert (
        await closure_scope(
            subject="person", closed_at=datetime.now(UTC), tenant_id=tid
        )
        == reply
    )
    assert route.calls.last.request.headers["X-Tenant-ID"] == str(tid)
    assert route.calls.last.request.headers["X-Account-Lifecycle-Token"] == "r" * 32


async def test_retirement_guard_can_query_same_service_with_single_connection(
    http_client, seed, closure_sync_url, authority, monkeypatch
):
    import asyncio
    import json

    from api.core import config
    from controlplane_identity.security.tenant_session_jwt import (
        mint_tenant_session_jwt,
    )
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    monkeypatch.setattr(
        config.settings,
        "api_key_exchange_jwt_secret",
        "isolated-single-pool-secret-more-than-32-characters",
    )
    monkeypatch.setenv("FASTAPI_ENV", "test")
    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://"),
        pool_size=1,
        max_overflow=0,
        pool_timeout=2,
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr("user_service.middleware.get_session_maker", lambda: maker)
    calls = []

    async def guard(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = next(
                int(line.split(b":", 1)[1])
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            payload = json.loads(await reader.readexactly(length))
            # The private callback uses the SAME app and one-connection pool.
            # Returning a stub here would miss connection starvation.
            result = await http_client.post(
                "/api/v1/internal/account-lifecycle/check",
                headers=authority,
                json=payload,
            )
            calls.append(result.status_code)
            body = result.content
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(guard, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_URL", f"http://127.0.0.1:{port}")
        token = mint_tenant_session_jwt(
            claims={"sub": "single-pool-operator", "permissions": ["operator:console"]},
            tenant_id=seed.ta,
        )
        response = await asyncio.wait_for(
            http_client.get(
                "/api/v1/operator/session",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID": str(seed.ta),
                },
            ),
            8,
        )
        assert response.status_code == 200, response.text
        assert calls == [200]
        assert engine.pool.checkedout() == 0
    finally:
        server.close()
        await server.wait_closed()
        await engine.dispose()


async def test_grant_scope_requires_original_account_tenant_and_complete_owner_receipts(
    http_client, closure_sync_url, authority, seed
):
    import json

    subject, key_id, lease_id = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()
    at = datetime.now(UTC)
    engine = create_engine(closure_sync_url)
    effects = {
        "profile_inventory_complete": True,
        "api_keys": {
            "keys": [
                {
                    "id": str(key_id),
                    "fingerprint": "a" * 64,
                    "purpose": "renter",
                    "secret": "never-return-this",
                }
            ]
        },
    }
    with engine.begin() as cx:
        cx.execute(
            text("INSERT INTO identity_retirements VALUES (:s,:at)"),
            {"s": subject, "at": at},
        )
        cx.execute(
            text("""INSERT INTO account_lifecycles
        (subject,requested_at,requested_by,source,state,closed_at,retry_at,financial_hold,effects)
        VALUES (:s,:at,:s,'self_service','closing',:at,:at,false,'{}'::jsonb)"""),
            {"s": subject, "at": at},
        )
        cx.execute(
            text(
                "INSERT INTO account_lifecycle_scopes VALUES (:t,:s,'[]'::jsonb,CAST(:effects AS jsonb))"
            ),
            {"t": seed.ta, "s": subject, "effects": json.dumps(effects)},
        )
    path = "/api/v1/internal/account-lifecycle/grant-scope"
    body = {"subject": subject, "tenant_id": str(seed.ta), "closed_at": at.isoformat()}
    headers = {**authority, "X-Tenant-ID": str(seed.ta)}
    try:
        assert (await http_client.post(path, headers=headers, json=body)).json() == {
            "allowed": False
        }
        effects["hypermesh"] = {"lease_ids": [str(lease_id)]}
        with engine.begin() as cx:
            cx.execute(
                text(
                    "UPDATE account_lifecycle_scopes SET effects=CAST(:effects AS jsonb) WHERE tenant_id=:t AND subject=:s"
                ),
                {"t": seed.ta, "s": subject, "effects": json.dumps(effects)},
            )
        assert (await http_client.post(path, headers=headers, json=body)).json() == {
            "allowed": False
        }
        effects["hypermesh"] = {
            "lease_ids": [str(lease_id)],
            "tickets_revoked": True,
            "new_selling_disabled": True,
        }
        with engine.begin() as cx:
            cx.execute(
                text(
                    "UPDATE account_lifecycle_scopes SET effects=CAST(:effects AS jsonb) WHERE tenant_id=:t AND subject=:s"
                ),
                {"t": seed.ta, "s": subject, "effects": json.dumps(effects)},
            )
        response = await http_client.post(path, headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert response.json() == {
            "allowed": True,
            "key_ids": [str(key_id)],
            "fingerprints": ["a" * 64],
            "lease_ids": [str(lease_id)],
        }
        assert "never-return-this" not in response.text
        other = await http_client.post(
            path,
            headers={**authority, "X-Tenant-ID": str(seed.tb)},
            json={**body, "tenant_id": str(seed.tb)},
        )
        assert other.json() == {"allowed": False}
        mismatched = await http_client.post(
            path, headers={**authority, "X-Tenant-ID": str(seed.tb)}, json=body
        )
        assert mismatched.json() == {"allowed": False}
        operator = await http_client.post(
            path, headers={**headers, "X-Account-Lifecycle-Token": "w" * 32}, json=body
        )
        assert operator.status_code == 403
    finally:
        with engine.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycle_scopes WHERE subject=:s"),
                {"s": subject},
            )
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
            cx.execute(
                text("DELETE FROM identity_retirements WHERE subject=:s"),
                {"s": subject},
            )
        engine.dispose()


@pytest.mark.parametrize("tenant_scope", [False, True])
async def test_financial_scope_keeps_frozen_ids_after_personal_erasure(
    http_client, closure_sync_url, authority, seed, tenant_scope
):
    import json

    subject = str(uuid.uuid4())
    identifier = str(uuid.uuid4())
    actual = datetime(2026, 1, 1, tzinfo=UTC)
    tid = seed.ta if tenant_scope else None
    path = "/api/v1/internal/account-lifecycle/financial-scope"
    headers = {**authority, **({"X-Tenant-ID": str(tid)} if tid else {})}
    body = {
        "subject": subject,
        "closed_at": actual.isoformat(),
        "tenant_id": str(tid) if tid else None,
    }
    eng = create_engine(closure_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text("INSERT INTO identity_retirements VALUES (:s,:at)"),
            {"s": subject, "at": actual},
        )
        cx.execute(
            text("""INSERT INTO account_lifecycles
          (subject,requested_at,requested_by,source,state,closed_at,retry_at,
           profile_deleted_at,financial_hold,hold_reference,effects)
          VALUES (:s,:at,:s,'self_service','deleted',:at,:at,:at,true,
            'private-hold-reference',cast(:effects AS jsonb))"""),
            {
                "s": subject,
                "at": actual,
                "effects": json.dumps(
                    {
                        "identity": {"disabled": True},
                        "platform_profile": {"user_ids": [identifier]},
                    }
                ),
            },
        )
        if tid:
            cx.execute(
                text("""INSERT INTO account_lifecycle_scopes
                (tenant_id,subject,user_ids,effects)
                VALUES (:t,:s,cast(:ids AS jsonb),cast(:proof AS jsonb))"""),
                {
                    "t": tid,
                    "s": subject,
                    "ids": json.dumps([identifier]),
                    "proof": json.dumps(
                        {
                            "profile_inventory_complete": True,
                            "profile_erasure": {"complete": True},
                            "api_keys": {"keys": []},
                        }
                    ),
                },
            )
    try:
        response = await http_client.post(path, headers=headers, json=body)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.json() == {
            "allowed": True,
            "user_ids": [identifier],
            "key_ids": [],
            "financial_hold": True,
        }
        assert "private-hold-reference" not in response.text
        assert (
            await http_client.post(
                path,
                headers={
                    **headers,
                    "X-Account-Lifecycle-Token": "w" * 32,
                },
                json=body,
            )
        ).status_code == 403
        assert (
            await http_client.post(
                path,
                headers={
                    **headers,
                    "X-Tenant-ID": str(seed.tb),
                },
                json=body,
            )
        ).json() == {"allowed": False}
        assert (
            await http_client.post(
                path,
                headers=headers,
                json={
                    **body,
                    "closed_at": datetime(2026, 1, 2, tzinfo=UTC).isoformat(),
                },
            )
        ).json() == {"allowed": False}
        with eng.begin() as cx:
            cx.execute(
                text("UPDATE account_lifecycles SET state='closing' WHERE subject=:s"),
                {"s": subject},
            )
        assert (await http_client.post(path, headers=headers, json=body)).json() == {
            "allowed": False
        }
    finally:
        with eng.begin() as cx:
            cx.execute(
                text("DELETE FROM account_lifecycle_scopes WHERE subject=:s"),
                {"s": subject},
            )
            cx.execute(
                text("DELETE FROM account_lifecycles WHERE subject=:s"), {"s": subject}
            )
            cx.execute(
                text("DELETE FROM identity_retirements WHERE subject=:s"),
                {"s": subject},
            )
        eng.dispose()


@pytest.fixture
async def http_client(app, auth_context):
    """Keep the legacy same-process pool regressions on the native reader.

    Public forwarding and the separate authority are covered in their own tests.
    This harness also retains ordinary operator routes for guard recursion tests.
    """
    from asgi_lifespan import LifespanManager
    from auth_service.deps import get_current_tenant, get_current_user
    from user_service.lifecycle_read import router

    app.router.routes[:] = [route for route in app.routes
                           if not getattr(route, "path", "").startswith("/api/v1/internal/account-lifecycle")]
    app.include_router(router, prefix="/api/v1")
    user, tenant = auth_context
    app.dependency_overrides[get_current_user] = user
    app.dependency_overrides[get_current_tenant] = tenant
    async with LifespanManager(app):
        # These historical tests substitute the module-level maker to exercise
        # RLS roles and a single connection. Private production apps set their
        # own maker and never replace the public application's global maker.
        del app.state.session_maker
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield client


async def test_retirement_only_identity_prevents_complete_denial_snapshot(
    http_client, closure_sync_url, authority, seed
):
    subject = str(uuid.uuid4())
    engine = create_engine(closure_sync_url)
    path = "/api/v1/internal/account-lifecycle/denials"
    headers = {**authority, "X-Tenant-ID": str(seed.ta)}
    assert (await http_client.get(path, headers=headers)).status_code == 200
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO identity_retirements(subject,retired_at) VALUES(:subject,now())"), {"subject": subject})
    try:
        response = await http_client.post("/api/v1/internal/account-lifecycle/check", headers=authority, json={"subject": subject})
        assert response.json() == {"blocked": True}
        for tenant in (seed.ta, seed.tb):
            response = await http_client.get(path, headers={**authority, "X-Tenant-ID": str(tenant)})
            assert response.status_code == 503
            assert response.json() == {"detail": "Account denial inventory incomplete"}
        with engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM account_lifecycles WHERE subject=:subject"), {"subject": subject}).scalar_one() == 0
    finally:
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM identity_retirements WHERE subject=:subject"), {"subject": subject})
        engine.dispose()
    assert (await http_client.get(path, headers=headers)).status_code == 200
