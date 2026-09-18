from __future__ import annotations

import uuid

import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import create_engine, text

from api.common.event_types import (
    GROUP_MEMBER_ADDED_V1,
    GROUP_MEMBER_REMOVED_V1,
    USER_CREATED_V1,
)
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
async def test_list_groups_only_current_tenant(
    http_client, tenant_headers, seed, migrated_sync_url
):
    gr = await http_client.post(
        "/api/v1/groups",
        headers=tenant_headers,
        json={"name": "ops", "description": "Ops team", "role_id": str(seed.ra)},
    )
    assert gr.status_code == 201, gr.text
    gid = gr.json()["id"]

    eng = create_engine(migrated_sync_url)
    other_id = uuid.uuid4()
    with eng.begin() as cx:
        cx.execute(
            text(
                "INSERT INTO groups (id, tenant_id, name, description, role_id) "
                "VALUES (:id, :tid, 'other-g', NULL, :rid)"
            ),
            {"id": other_id, "tid": seed.tb, "rid": seed.rb},
        )

    lr = await http_client.get("/api/v1/groups", headers=tenant_headers)
    assert lr.status_code == 200
    body = lr.json()
    names = {g["name"] for g in body["items"]}
    assert "ops" in names
    assert "other-g" not in names
    assert body["total"] >= 1

    one = await http_client.get(f"/api/v1/groups/{gid}", headers=tenant_headers)
    assert one.status_code == 200
    assert one.json()["name"] == "ops"
    assert one.json()["tenant_id"] == str(seed.ta)

    missing = await http_client.get(
        f"/api/v1/groups/{other_id}", headers=tenant_headers
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_list_groups_pagination_and_search(http_client, tenant_headers, seed):
    for i in range(3):
        r = await http_client.post(
            "/api/v1/groups",
            headers=tenant_headers,
            json={
                "name": f"page-g{i}",
                "description": f"desc{i}",
                "role_id": str(seed.ra),
            },
        )
        assert r.status_code == 201, r.text

    r0 = await http_client.get(
        "/api/v1/groups",
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
        "/api/v1/groups",
        headers=tenant_headers,
        params={"q": "page-g1", "limit": 50, "offset": 0},
    )
    assert r1.status_code == 200
    names = {g["name"] for g in r1.json()["items"]}
    assert "page-g1" in names


@pytest.mark.asyncio
async def test_list_organizations_only_current_tenant(
    http_client, tenant_headers, seed, migrated_sync_url
):
    empty = await http_client.get("/api/v1/organizations", headers=tenant_headers)
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    assert empty.json()["total"] == 0

    cr = await http_client.post(
        "/api/v1/organizations",
        headers=tenant_headers,
        json={"legal_name": "Acme LLC"},
    )
    assert cr.status_code == 201, cr.text
    oid = cr.json()["id"]

    eng = create_engine(migrated_sync_url)
    other_id = uuid.uuid4()
    with eng.begin() as cx:
        cx.execute(
            text(
                "INSERT INTO organizations (id, tenant_id, legal_name) "
                "VALUES (:id, :tid, 'Other LLC')"
            ),
            {"id": other_id, "tid": seed.tb},
        )

    lr = await http_client.get("/api/v1/organizations", headers=tenant_headers)
    assert lr.status_code == 200
    names = {o["legal_name"] for o in lr.json()["items"]}
    assert "Acme LLC" in names
    assert "Other LLC" not in names

    one = await http_client.get(
        f"/api/v1/organizations/{oid}", headers=tenant_headers
    )
    assert one.status_code == 200
    assert one.json()["legal_name"] == "Acme LLC"
    assert one.json()["tenant_id"] == str(seed.ta)

    missing = await http_client.get(
        f"/api/v1/organizations/{other_id}", headers=tenant_headers
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_list_organizations_pagination_and_search(
    http_client, tenant_headers
):
    for i in range(3):
        r = await http_client.post(
            "/api/v1/organizations",
            headers=tenant_headers,
            json={"legal_name": f"Page Org {i}"},
        )
        assert r.status_code == 201, r.text

    r0 = await http_client.get(
        "/api/v1/organizations",
        headers=tenant_headers,
        params={"limit": 2, "offset": 0},
    )
    assert r0.status_code == 200
    b0 = r0.json()
    assert b0["total"] >= 3
    assert len(b0["items"]) == 2

    r1 = await http_client.get(
        "/api/v1/organizations",
        headers=tenant_headers,
        params={"q": "Page Org 1", "limit": 50, "offset": 0},
    )
    assert r1.status_code == 200
    names = {o["legal_name"] for o in r1.json()["items"]}
    assert "Page Org 1" in names


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


@pytest.mark.asyncio
async def test_assign_and_remove_user_role(http_client, tenant_headers, seed):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "roleuser@example.com",
            "first_name": "Role",
            "last_name": "User",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201, ur.text
    uid = ur.json()["id"]
    assert ur.json()["role_id"] is None

    assigned = await http_client.patch(
        f"/api/v1/users/{uid}/assign_role",
        headers=tenant_headers,
        json={"role_id": str(seed.ra)},
    )
    assert assigned.status_code == 202, assigned.text
    assert assigned.json()["role_id"] == str(seed.ra)

    listed = await http_client.get("/api/v1/users", headers=tenant_headers)
    assert listed.status_code == 200
    match = next(u for u in listed.json()["items"] if u["id"] == uid)
    assert match["role_id"] == str(seed.ra)

    again = await http_client.patch(
        f"/api/v1/users/{uid}/assign_role",
        headers=tenant_headers,
        json={"role_id": str(seed.ra)},
    )
    assert again.status_code == 409

    missing_role = await http_client.patch(
        f"/api/v1/users/{uid}/assign_role",
        headers=tenant_headers,
        json={"role_id": str(uuid.uuid4())},
    )
    assert missing_role.status_code == 404

    other_role = await http_client.patch(
        f"/api/v1/users/{uid}/assign_role",
        headers=tenant_headers,
        json={"role_id": str(seed.rb)},
    )
    assert other_role.status_code == 404

    removed = await http_client.patch(
        f"/api/v1/users/{uid}/remove_role",
        headers=tenant_headers,
        json={"role_id": str(seed.ra)},
    )
    assert removed.status_code == 202, removed.text
    assert removed.json()["role_id"] is None

    already = await http_client.patch(
        f"/api/v1/users/{uid}/remove_role",
        headers=tenant_headers,
        json={"role_id": str(seed.ra)},
    )
    assert already.status_code == 409

    missing_user = await http_client.patch(
        f"/api/v1/users/{uuid.uuid4()}/assign_role",
        headers=tenant_headers,
        json={"role_id": str(seed.ra)},
    )
    assert missing_user.status_code == 404


@pytest.mark.asyncio
async def test_portal_controls_admin_can_mint_and_invite(
    http_client, tenant_headers
):
    r = await http_client.get("/api/v1/me/portal-controls", headers=tenant_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_admin"] is True
    assert body["can_invite_members"] is True
    assert body["can_assign_group"] is True
    assert body["can_mint_keys"] is True
    assert body["can_checkout"] is False
    assert body["can_see_host_status"] is False
    assert body["can_see_leases"] is False
    assert body["can_use_ir_door"] is True
    assert body["can_export_ir_receipts"] is True


@pytest.mark.asyncio
async def test_ir_group_grants_are_separate_on_portal_controls(
    app, http_client, tenant_headers, seed
):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "ir-actor@example.com",
            "first_name": "Ir",
            "last_name": "Door",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201, ur.text
    uid = ur.json()["id"]
    ir_g = await http_client.post(
        "/api/v1/groups",
        headers=tenant_headers,
        json={"name": "ir", "description": "IR door", "role_id": str(seed.ra)},
    )
    assert ir_g.status_code == 201, ir_g.text
    export_g = await http_client.post(
        "/api/v1/groups",
        headers=tenant_headers,
        json={
            "name": "ir_export",
            "description": "IR receipts",
            "role_id": str(seed.ra),
        },
    )
    assert export_g.status_code == 201, export_g.text
    added = await http_client.post(
        f"/api/v1/users/{uid}/groups/{ir_g.json()['id']}",
        headers=tenant_headers,
    )
    assert added.status_code == 201, added.text

    async def _ir_member() -> AuthMeResponse:
        return AuthMeResponse(
            sub="33333333-3333-3333-3333-333333333333",
            email="ir-actor@example.com",
            tenant_id=seed.ta,
            roles=["user"],
            groups=[],
            scopes=[],
        )

    app.dependency_overrides[get_current_user] = _ir_member
    try:
        door_only = await http_client.get(
            "/api/v1/me/portal-controls", headers=tenant_headers
        )
        assert door_only.status_code == 200, door_only.text
        body = door_only.json()
        assert body["can_use_ir_door"] is True
        assert body["can_export_ir_receipts"] is False
        assert body["org_admin"] is False
    finally:
        async def _admin() -> AuthMeResponse:
            return AuthMeResponse(
                sub="11111111-1111-1111-1111-111111111111",
                email="actor@example.com",
                tenant_id=seed.ta,
                roles=["admin"],
                scopes=[],
            )

        app.dependency_overrides[get_current_user] = _admin

    export_add = await http_client.post(
        f"/api/v1/users/{uid}/groups/{export_g.json()['id']}",
        headers=tenant_headers,
    )
    assert export_add.status_code == 201, export_add.text
    revoke_door = await http_client.delete(
        f"/api/v1/users/{uid}/groups/{ir_g.json()['id']}",
        headers=tenant_headers,
    )
    assert revoke_door.status_code == 204, revoke_door.text

    app.dependency_overrides[get_current_user] = _ir_member
    try:
        export_only = await http_client.get(
            "/api/v1/me/portal-controls", headers=tenant_headers
        )
        assert export_only.status_code == 200, export_only.text
        body = export_only.json()
        assert body["can_use_ir_door"] is False
        assert body["can_export_ir_receipts"] is True
    finally:
        async def _admin() -> AuthMeResponse:
            return AuthMeResponse(
                sub="11111111-1111-1111-1111-111111111111",
                email="actor@example.com",
                tenant_id=seed.ta,
                roles=["admin"],
                scopes=[],
            )

        app.dependency_overrides[get_current_user] = _admin


@pytest.mark.asyncio
async def test_group_members_list_and_remove(
    http_client, tenant_headers, event_sink, seed
):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "renter@example.com",
            "first_name": "R",
            "last_name": "Enter",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201
    uid = ur.json()["id"]
    gr = await http_client.post(
        "/api/v1/groups",
        headers=tenant_headers,
        json={"name": "renter", "description": "Renter group", "role_id": str(seed.ra)},
    )
    assert gr.status_code == 201, gr.text
    gid = gr.json()["id"]
    added = await http_client.post(
        f"/api/v1/users/{uid}/groups/{gid}",
        headers=tenant_headers,
    )
    assert added.status_code == 201, added.text

    listed = await http_client.get(
        f"/api/v1/groups/{gid}/members",
        headers=tenant_headers,
    )
    assert listed.status_code == 200, listed.text
    emails = {m["email"] for m in listed.json()["items"]}
    assert "renter@example.com" in emails

    mine = await http_client.get(
        f"/api/v1/users/{uid}/groups",
        headers=tenant_headers,
    )
    assert mine.status_code == 200, mine.text
    assert {g["name"] for g in mine.json()["items"]} == {"renter"}

    event_sink.clear()
    removed = await http_client.delete(
        f"/api/v1/users/{uid}/groups/{gid}",
        headers=tenant_headers,
    )
    assert removed.status_code == 204, removed.text
    assert any(e["event_type"] == GROUP_MEMBER_REMOVED_V1 for e in event_sink)

    empty = await http_client.get(
        f"/api/v1/groups/{gid}/members",
        headers=tenant_headers,
    )
    assert empty.json()["items"] == []


@pytest.mark.asyncio
async def test_invite_and_assign_forbidden_without_org_admin(
    app, http_client, tenant_headers, seed
):
    ur = await http_client.post(
        "/api/v1/users",
        headers=tenant_headers,
        json={
            "email": "guest-actor-target@example.com",
            "first_name": "G",
            "last_name": "T",
            "gender": "unspecified",
            "is_active": True,
        },
    )
    assert ur.status_code == 201
    uid = ur.json()["id"]
    gr = await http_client.post(
        "/api/v1/groups",
        headers=tenant_headers,
        json={"name": "host", "description": None, "role_id": str(seed.ra)},
    )
    assert gr.status_code == 201
    gid = gr.json()["id"]

    async def _guest() -> AuthMeResponse:
        return AuthMeResponse(
            sub="22222222-2222-2222-2222-222222222222",
            email="guest@example.com",
            tenant_id=seed.ta,
            roles=["guest"],
            groups=[],
            scopes=[],
        )

    app.dependency_overrides[get_current_user] = _guest
    try:
        denied = await http_client.post(
            f"/api/v1/users/{uid}/groups/{gid}",
            headers=tenant_headers,
        )
        assert denied.status_code == 403
        controls = await http_client.get(
            "/api/v1/me/portal-controls", headers=tenant_headers
        )
        assert controls.status_code == 200
        body = controls.json()
        assert body["org_admin"] is False
        assert body["can_mint_keys"] is False
        assert body["can_checkout"] is False
        assert body["can_see_host_status"] is False
        assert body["can_use_ir_door"] is False
        assert body["can_export_ir_receipts"] is False
        invite = await http_client.post(
            "/api/v1/users",
            headers=tenant_headers,
            json={
                "email": "guest-invite@example.com",
                "first_name": "No",
                "last_name": "Invite",
                "gender": "unspecified",
                "is_active": True,
            },
        )
        assert invite.status_code == 403
    finally:
        async def _admin() -> AuthMeResponse:
            return AuthMeResponse(
                sub="11111111-1111-1111-1111-111111111111",
                email="actor@example.com",
                tenant_id=seed.ta,
                roles=["admin"],
                scopes=[],
            )

        app.dependency_overrides[get_current_user] = _admin
