"""Real PostgreSQL jobs and bounded owner HTTP replies across partial retries."""

import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import text
from test_closure_jobs import jobs as jobs  # noqa: PLC0414
from test_closure_jobs import jobs_url as jobs_url  # noqa: PLC0414
from test_closure_jobs import simulated_database_clock
from user_service.closure_clients import ClosureOwners, OwnerUnavailable
from user_service.closure_processor import ClosureProcessor
from user_service.models import AccountLifecycle


@pytest.mark.parametrize("failure_mode", ["http", "capability_type"])
async def test_failed_receiver_does_not_starve_keys_or_other_receivers(
    jobs, monkeypatch, failure_mode
):
    store, clock = jobs
    await simulated_database_clock(store, clock, monkeypatch)
    tenant, other = uuid.uuid4(), uuid.uuid4()
    subject, bad, good = str(uuid.uuid4()), uuid.uuid4(), uuid.uuid4()
    async with store.transaction() as session:
        for tid in (tenant, other):
            await session.execute(
                text("INSERT INTO tenants(id,name,is_active) VALUES (:t,:n,false)"),
                {"t": tid, "n": str(tid)},
            )
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://keys.example")
    monkeypatch.setenv("ACCOUNT_CLOSURE_HYPERMESH_URL", "https://mesh.example")
    for gateway in (bad, good):
        monkeypatch.setenv(
            f"ACCOUNT_CLOSURE_GATEWAY_{gateway.hex.upper()}_URL",
            f"https://{gateway.hex}.example",
        )
    calls, disabled = [], []
    unavailable = [True]
    key_id = uuid.uuid4()

    class Identity:
        async def disable(self, target):
            assert store.maker.kw["bind"].pool.checkedout() == 0
            disabled.append(target)

    async def reply(request):
        import json

        assert store.maker.kw["bind"].pool.checkedout() == 0
        assert request.headers["X-Account-Lifecycle-Token"] == "w" * 32
        tid = request.headers.get("X-Tenant-ID")
        body = json.loads(request.content) if request.content else {}
        action = request.url.path.rsplit("/", 1)[-1]
        calls.append((request.url.host, action, tid))
        if request.url.host == "keys.example":
            if action == "owner-inventory":
                return httpx.Response(
                    200,
                    json={
                        "keys": [
                            {
                                "tenant_id": str(tenant),
                                "id": str(key_id),
                                "fingerprint": "a" * 64,
                                "purpose": "renter",
                            }
                        ]
                    },
                )
            return httpx.Response(
                200,
                json={
                    "keys": (
                        [
                            {
                                "id": str(key_id),
                                "fingerprint": "a" * 64,
                                "purpose": "renter",
                            }
                        ]
                        if tid == str(tenant)
                        else []
                    )
                },
            )
        if request.url.host == "mesh.example":
            if action == "gateway-roster":
                return httpx.Response(
                    200,
                    json={
                        "complete": True,
                        "tenant_id": tid,
                        "gateway_ids": [str(bad), str(good)]
                        if tid == str(tenant)
                        else [],
                    },
                )
            return httpx.Response(
                200,
                json={
                    "model_ids": [],
                    "lease_ids": [],
                    "device_ids": [],
                    "registration_ids": [],
                    "organization_ids": [],
                    "has_resources": False,
                    "tickets_revoked": True,
                    "new_selling_disabled": True,
                    "model_closure_recorded": False,
                },
            )
        gateway = body["expected_gateway_id"]
        assert tid == body["tenant_id"] == str(tenant)
        assert body["subject"] == subject
        assert body["closed_at"] == clock[0].isoformat() or not unavailable[0]
        if gateway == str(bad) and unavailable[0] and failure_mode == "http":
            return httpx.Response(503, json={"error": "provider-private-error"})
        answer = {"gateway_id": gateway}
        if action == "owner-inventory":
            answer.update(
                has_resources=False,
                history={"present": False},
                training={"present": False},
            )
            if (
                gateway == str(bad)
                and unavailable[0]
                and failure_mode == "capability_type"
            ):
                answer["capabilities"] = {"history": [], "training": "disabled"}
        else:
            assert action in {"deny-principal", "deny-grants"}
            if action == "deny-grants":
                assert body["key_ids"] == [str(key_id)]
                assert body["fingerprints"] == ["a" * 64]
                # prepare_scope writes the tenant row before any grant denial.
                async with store.transaction(uuid.UUID(tid)) as session:
                    from user_service.models import AccountLifecycleScope

                    scope = await session.get(
                        AccountLifecycleScope, (uuid.UUID(tid), subject)
                    )
                    assert scope is not None
                    assert scope.effects.get("profile_inventory_complete") is True
            answer["denial_persisted"] = True
        return httpx.Response(200, json=answer)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(reply), trust_env=False
    ) as client:
        processor = ClosureProcessor(store, Identity(), ClosureOwners(client))
        await store.request(subject, subject, "self_service")
        work = await store.claim(subject)
        assert await processor.close(work) is None
        assert disabled == [subject]
        for tid in (tenant, other):
            async with store.transaction(tid) as session:
                from user_service.models import AccountLifecycleScope

                row = await session.get(AccountLifecycleScope, (tid, subject))
                assert "api_keys" in row.effects and "hypermesh" in row.effects
        async with store.transaction() as session:
            row = await session.get(AccountLifecycle, subject)
            original = row.closed_at
            assert row.state == "closing" and row.last_error == "owner_unavailable"
            assert row.profile_deleted_at is None and row.financial_deleted_at is None
        assert (good.hex + ".example", "owner-inventory", str(tenant)) in calls
        key_positions = [
            i
            for i, call in enumerate(calls)
            if call[0] == "keys.example" and call[1] == "close-owner"
        ]
        gateway_positions = [
            i
            for i, call in enumerate(calls)
            if call[0].endswith(".example")
            and call[0] not in {"keys.example", "mesh.example"}
        ]
        assert max(key_positions) < min(gateway_positions)
        count_good = sum(call[0] == good.hex + ".example" for call in calls)
        unavailable[0] = False
        clock[0] += timedelta(seconds=31)
        replacement = await store.claim(subject)

        async def unexpected_second_transaction(*args, **kwargs):
            raise AssertionError("Closed state must commit its own retry and release")

        monkeypatch.setattr(store, "release", unexpected_second_transaction)
        closed = await processor.close(replacement)
        assert closed.state == "closed" and closed.closed_at == original
        assert disabled == [subject]
        assert sum(call[0] == good.hex + ".example" for call in calls) == count_good
        assert not any(
            call[1] == "close-owner" and call[0] == good.hex + ".example"
            for call in calls
        )
        async with store.transaction() as session:
            row = await session.get(AccountLifecycle, subject)
            assert row.effects["scope_discovery"] is True
            assert row.retry_at == original + timedelta(days=89)
            assert row.claim_id is None


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"keys": "not-a-list"},
        {"keys": [{"id": "bad", "purpose": "renter"}]},
    ],
)
async def test_untyped_key_success_reply_is_not_a_revocation_receipt(
    monkeypatch, answer
):
    from datetime import UTC, datetime

    from user_service.closure_jobs import ClosureWork

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://keys.example")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=answer))
    ) as client:
        owners = ClosureOwners(client)
        with pytest.raises(OwnerUnavailable, match="owner_unavailable"):
            await owners.close_keys(
                ClosureWork("subject", uuid.uuid4(), "closing", datetime.now(UTC), {}),
                uuid.uuid4(),
            )


@pytest.mark.parametrize(
    "change",
    [
        {"gateway_id": str(uuid.uuid4())},
        {"gateway_id": None},
        {"denial_persisted": 1},
        {"denial_persisted": "true"},
    ],
)
async def test_gateway_success_requires_exact_receiver_and_boolean_ack(
    monkeypatch, change
):
    from datetime import UTC, datetime

    from user_service.closure_jobs import ClosureWork

    gateway, tenant = uuid.uuid4(), uuid.uuid4()
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv(
        f"ACCOUNT_CLOSURE_GATEWAY_{gateway.hex.upper()}_URL", "https://receiver.example"
    )
    answer = {"gateway_id": str(gateway), "denial_persisted": True, **change}
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=answer))
    ) as client:
        with pytest.raises(OwnerUnavailable):
            await ClosureOwners(client).gateway(
                ClosureWork("subject", uuid.uuid4(), "closing", datetime.now(UTC), {}),
                tenant,
                gateway,
                "deny-principal",
            )


async def test_owner_redirect_is_never_followed_and_payload_is_bounded(monkeypatch):
    from user_service import closure_clients

    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_KEYS_URL", "https://keys.example")
    calls = []

    def redirect(request):
        calls.append(request.url.host)
        return httpx.Response(307, headers={"Location": "https://untrusted.example"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(redirect), follow_redirects=True
    ) as client:
        with pytest.raises(OwnerUnavailable):
            await ClosureOwners(client).call("KEYS", "/private", body={})
    assert calls == ["keys.example"]
    monkeypatch.setattr(closure_clients, "MAX_RESPONSE_BYTES", 3)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"keys": []}))
    ) as client:
        with pytest.raises(OwnerUnavailable):
            await ClosureOwners(client).call("KEYS", "/private", body={})


async def test_failed_gateway_attempts_renew_claim_before_later_healthy_receivers(
    jobs, monkeypatch
):
    store, clock = jobs
    await simulated_database_clock(store, clock, monkeypatch)
    subject, tenant = str(uuid.uuid4()), uuid.uuid4()
    async with store.transaction() as session:
        await session.execute(
            text("INSERT INTO tenants(id,name,is_active) VALUES (:t,:n,true)"),
            {"t": tenant, "n": str(tenant)},
        )

    class Identity:
        async def disable(self, subject):
            return None

    gateways = [uuid.UUID(int=index) for index in range(1, 16)]
    called = []

    class Owners:
        async def key_tenants(self, work):
            return []

        async def close_keys(self, work, tid):
            return {"keys": []}

        async def close_hypermesh(self, work, tid):
            return {
                "model_ids": [],
                "lease_ids": [],
                "tickets_revoked": True,
                "new_selling_disabled": True,
            }

        async def gateways(self, tid):
            return gateways if tid == tenant else []

        async def gateway(self, work, tid, gateway, action, **kwargs):
            called.append(gateway)
            if gateway != gateways[-1]:
                clock[0] += timedelta(seconds=5)
                raise OwnerUnavailable()
            return (
                {"has_resources": False}
                if action == "owner-inventory"
                else {"denial_persisted": True}
            )

    await store.request(subject, subject, "self_service")
    work = await store.claim(subject)
    processor = ClosureProcessor(store, Identity(), Owners())
    assert await processor.close(work) is None
    assert gateways[-1] in called  # >60 seconds of failures preceded this receiver.
    async with store.transaction(tenant) as session:
        from user_service.models import AccountLifecycleScope

        scope = await session.get(AccountLifecycleScope, (tenant, subject))
        assert scope.effects["gateway:" + str(gateways[-1])]["closed"] is True
    async with store.transaction() as session:
        row = await session.get(AccountLifecycle, subject)
        assert row.claim_id is None and row.state == "closing"


@pytest.mark.parametrize("mode", [[], {}, None, False, 1])
async def test_malformed_capability_mode_is_normalized_to_owner_failure(
    monkeypatch, mode
):
    from datetime import UTC, datetime

    from user_service.closure_jobs import ClosureWork

    gateway = uuid.uuid4()
    monkeypatch.setenv("ACCOUNT_CLOSURE_GUARD_TOKEN", "r" * 32)
    monkeypatch.setenv("ACCOUNT_CLOSURE_OPERATIONS_TOKEN", "w" * 32)
    monkeypatch.setenv(
        f"ACCOUNT_CLOSURE_GATEWAY_{gateway.hex.upper()}_URL", "https://receiver.example"
    )
    body = {
        "gateway_id": str(gateway),
        "has_resources": False,
        "history": {"present": False, "disabled": True},
        "training": {"present": False, "disabled": True},
        "capabilities": {"history": mode, "training": "disabled"},
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    ) as client:
        with pytest.raises(OwnerUnavailable):
            await ClosureOwners(client).gateway(
                ClosureWork("subject", uuid.uuid4(), "closing", datetime.now(UTC), {}),
                uuid.uuid4(),
                gateway,
                "owner-inventory",
            )
