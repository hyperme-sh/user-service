from __future__ import annotations

import uuid

import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import create_engine, text

from api.common.event_types import GROUP_MEMBER_ADDED_V1, USER_CREATED_V1
from auth_service.deps import get_current_tenant, get_current_user
from auth_service.schemas import AuthMeResponse


@pytest.mark.asyncio
async def test_create_user_publishes_user_created(
    http_client, tenant_headers, event_sink, seed
):
    r = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "new@example.com",
            "first_name": "New",
            "last_name": "User",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "new@example.com"
    assert body["tenant_id"] == str(seed.ta)
    types = [e["event_type"] for e in event_sink]
    assert USER_CREATED_V1 in types
    ev = next(e for e in event_sink if e["event_type"] == USER_CREATED_V1)
    assert ev["payload"]["email"] == "new@example.com"


@pytest.mark.asyncio
async def test_list_users_only_current_tenant(
    app, http_client, tenant_headers, seed, migrated_sync_url
):
    r = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "a@example.com",
            "first_name": "A",
            "last_name": "One",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert r.status_code == 201
    eng = create_engine(migrated_sync_url)
    other_id = uuid.uuid4()
    with eng.begin() as cx:
        cx.execute(
            text(
                "INSERT INTO users (id, tenant_id, first_name, last_name, email, gender, is_active) "
                "VALUES (:id, :tid, 'B', 'User', 'b@other.com', 'unspecified', true)"
            ),
            {"id": other_id, "tid": seed.tb},
        )
    r2 = await http_client.get("/api/v1/users", headers=tenant_headers)
    assert r2.status_code == 200
    body = r2.json()
    assert "items" in body
    emails = {u["email"] for u in body["items"]}
    assert "a@example.com" in emails
    assert "b@other.com" not in emails


@pytest.mark.asyncio
async def test_add_user_to_group_publishes_event(
    http_client, tenant_headers, event_sink, seed
):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "member@example.com",
            "first_name": "M",
            "last_name": "U",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201
    uid = ur.json()["id"]
    gr = await http_client.post(
        "/api/v1/groups",
        headers=tenant_headers,
        json={"name": "g1", "description": None, "role_id": str(seed.ra)},
    )
    assert gr.status_code == 201, gr.text
    gid = gr.json()["id"]
    event_sink.clear()
    ar = await http_client.post(
        f"/api/v1/users/{uid}/groups/{gid}",
        headers=tenant_headers,
    )
    assert ar.status_code == 201, ar.text
    assert any(e["event_type"] == GROUP_MEMBER_ADDED_V1 for e in event_sink)
    ev = next(e for e in event_sink if e["event_type"] == GROUP_MEMBER_ADDED_V1)
    assert ev["payload"]["user_id"] == uid
    assert ev["payload"]["group_id"] == gid


@pytest.mark.asyncio
async def test_patch_user_sociacl(http_client, tenant_headers, seed):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "soc@example.com",
            "first_name": "S",
            "last_name": "O",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201
    uid = ur.json()["id"]
    pr = await http_client.patch(
        f"/api/v1/users/{uid}",
        headers=tenant_headers,
        json={
            "sociacl_attributes": {
                "political_view": "unspecified",
                "verification_level": 2,
            }
        },
    )
    assert pr.status_code == 200, pr.text
    assert pr.json()["sociacl_attributes"]["verification_level"] == 2


@pytest.mark.asyncio
async def test_soft_delete_excludes_from_list(http_client, tenant_headers):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "gone@example.com",
            "first_name": "G",
            "last_name": "One",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201
    uid = ur.json()["id"]
    dr = await http_client.delete(
        f"/api/v1/users/{uid}",
        headers=tenant_headers,
    )
    assert dr.status_code == 204
    lr = await http_client.get("/api/v1/users", headers=tenant_headers)
    assert lr.status_code == 200
    assert all(u["id"] != uid for u in lr.json()["items"])


@pytest.mark.asyncio
async def test_tenant_header_mismatch_returns_403(app, seed, event_sink):
    async def _user() -> AuthMeResponse:
        return AuthMeResponse(
            sub="22222222-2222-2222-2222-222222222222",
            email="x@example.com",
            tenant_id=seed.ta,
            roles=[],
            scopes=[],
        )

    async def _tenant() -> uuid.UUID:
        return seed.ta

    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_current_tenant] = _tenant

    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get(
                "/api/v1/users",
                headers={
                    "Authorization": "Bearer t",
                    "X-Tenant-ID": str(seed.tb),
                },
            )
            assert r.status_code == 403
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_tenant, None)


@pytest.mark.asyncio
async def test_list_users_pagination_and_search(http_client, tenant_headers):
    for i in range(3):
        r = await http_client.post(
            "/api/v1/users",
            headers=tenant_headers,
            json={
                "email": f"page{i}@example.com",
                "first_name": "P",
                "last_name": f"User{i}",
                "gender": "unspecified",
                "is_active": True,
            },
        )
        assert r.status_code == 201, r.text

    r0 = await http_client.get(
        "/api/v1/users",
        headers=tenant_headers,
        params={"limit": 2, "offset": 0},
    )
    assert r0.status_code == 200
    b0 = r0.json()
    assert b0["total"] >= 3
    assert len(b0["items"]) == 2
    assert b0["limit"] == 2
    assert b0["offset"] == 0

    r1 = await http_client.get(
        "/api/v1/users",
        headers=tenant_headers,
        params={"q": "page1@", "limit": 50, "offset": 0},
    )
    assert r1.status_code == 200
    emails = {u["email"] for u in r1.json()["items"]}
    assert "page1@example.com" in emails
