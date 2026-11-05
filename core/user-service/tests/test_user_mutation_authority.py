"""HTTP mutations recheck durable authority despite still-valid token claims."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text

from auth_service.deps import get_current_tenant, get_current_user
from auth_service.schemas import AuthMeResponse


@pytest.fixture
def authority(app, http_client, migrated_sync_url):
    engine = create_engine(migrated_sync_url)
    state = SimpleNamespace(
        tenant=uuid.uuid4(), foreign_tenant=uuid.uuid4(), admin=uuid.uuid4(),
        member=uuid.uuid4(), actor=uuid.uuid4(), target=uuid.uuid4(),
        foreign_user=uuid.uuid4(), subject=f"issuer-subject-{uuid.uuid4()}",
    )
    state.claim_sub = state.subject
    state.claim_roles = ["admin"]
    state.email = f"{state.actor}@example.com"
    state.headers = {"Authorization": "Bearer stale-token", "X-Tenant-ID": str(state.tenant)}

    def execute(sql, **params):
        with engine.begin() as connection:
            return connection.execute(text(sql), params)

    state.execute = execute

    def snapshot():
        with engine.connect() as connection:
            return list(connection.execute(text(
                "SELECT id, tenant_id, keycloak_sub, first_name, last_name, "
                "is_active, deleted_at, role_id, sociacl_attributes::text FROM users "
                "WHERE tenant_id IN (:tenant, :foreign) ORDER BY id"
            ), {"tenant": state.tenant, "foreign": state.foreign_tenant}))

    state.snapshot = snapshot
    for tenant in (state.tenant, state.foreign_tenant):
        execute("INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)",
                id=tenant, name=str(tenant))
    for role, name in ((state.admin, "admin"), (state.member, "member")):
        execute("INSERT INTO roles (id, tenant_id, name, permissions) VALUES (:id, :tenant, :name, '[]'::jsonb)",
                id=role, tenant=state.tenant, name=name)
    for user, tenant, sub, role in (
        (state.actor, state.tenant, state.subject, state.admin),
        (state.target, state.tenant, None, state.member),
        (state.foreign_user, state.foreign_tenant, f"foreign-{state.subject}", None),
    ):
        execute("INSERT INTO users (id, tenant_id, keycloak_sub, email, first_name, last_name, gender, is_active, role_id) "
                "VALUES (:id, :tenant, :sub, :email, 'Original', 'Name', 'unspecified', true, :role)",
                id=user, tenant=tenant, sub=sub, email=f"{user}@example.com", role=role)

    async def actor():
        return AuthMeResponse(sub=state.claim_sub, email=state.email,
                              tenant_id=state.tenant, roles=state.claim_roles, scopes=[])

    async def tenant():
        return state.tenant

    app.dependency_overrides[get_current_user] = actor
    app.dependency_overrides[get_current_tenant] = tenant
    try:
        yield state
    finally:
        for tid in (state.tenant, state.foreign_tenant):
            execute("DELETE FROM users WHERE tenant_id=:tenant", tenant=tid)
            execute("DELETE FROM roles WHERE tenant_id=:tenant", tenant=tid)
            execute("DELETE FROM tenants WHERE id=:tenant", tenant=tid)
        engine.dispose()


def revoke(state, reason):
    changes = {
        "role_removed": "role_id=NULL", "inactive": "is_active=false",
        "deleted": "deleted_at=now()", "unbound": "keycloak_sub=NULL",
    }
    if reason in changes:
        state.execute(f"UPDATE users SET {changes[reason]} WHERE id=:id", id=state.actor)
    elif reason == "tenant_inactive":
        state.execute("UPDATE tenants SET is_active=false WHERE id=:id", id=state.tenant)
    elif reason == "foreign_subject":
        state.claim_sub = f"foreign-{state.subject}"
    elif reason == "local_id_subject":
        state.claim_sub = str(state.actor)
    elif reason == "removed":
        state.execute("DELETE FROM users WHERE id=:id", id=state.actor)
    else:
        raise AssertionError(reason)


@pytest.mark.parametrize("operation", ["create", "delete"])
@pytest.mark.parametrize("reason", [
    "role_removed", "inactive", "deleted", "removed", "unbound", "tenant_inactive", "foreign_subject",
])
async def test_stale_admin_cannot_create_or_delete(http_client, authority, event_sink, operation, reason):
    s = authority
    revoke(s, reason)
    before = s.snapshot()
    if operation == "create":
        response = await http_client.post("/api/v1/users", headers=s.headers, json={
            "email": "refused@example.com", "first_name": "Denied", "last_name": "Invite",
        })
    else:
        response = await http_client.delete(f"/api/v1/users/{s.target}", headers=s.headers)
    assert response.status_code == 403, response.text
    assert event_sink == []
    assert s.snapshot() == before


@pytest.mark.parametrize("operation", ["create", "delete"])
async def test_current_admin_can_mutate_without_admin_token_claim(http_client, authority, operation):
    s = authority
    s.claim_roles = []
    if operation == "create":
        response = await http_client.post("/api/v1/users", headers=s.headers, json={
            "email": f"new-{s.actor}@example.com", "first_name": "Allowed", "last_name": "Invite",
        })
        assert response.status_code == 201, response.text
    else:
        response = await http_client.delete(f"/api/v1/users/{s.target}", headers=s.headers)
        assert response.status_code == 204, response.text


@pytest.mark.parametrize("operation", ["create", "delete", "update"])
async def test_user_mutations_reject_tenant_header_mismatch(http_client, authority, operation):
    s = authority
    headers = dict(s.headers, **{"X-Tenant-ID": str(s.foreign_tenant)})
    before = s.snapshot()
    if operation == "create":
        response = await http_client.post("/api/v1/users", headers=headers, json={
            "email": "mismatch@example.com", "first_name": "Denied", "last_name": "Invite",
        })
    elif operation == "delete":
        response = await http_client.delete(f"/api/v1/users/{s.foreign_user}", headers=headers)
    else:
        response = await http_client.patch(f"/api/v1/users/{s.foreign_user}", headers=headers,
                                          json={"first_name": "Changed"})
    assert response.status_code == 403, response.text
    assert s.snapshot() == before


@pytest.mark.parametrize("reason", [
    "role_removed", "inactive", "deleted", "removed", "unbound", "tenant_inactive", "foreign_subject",
])
async def test_profile_other_user_requires_current_admin(http_client, authority, reason):
    s = authority
    revoke(s, reason)
    before = s.snapshot()
    response = await http_client.patch(f"/api/v1/users/{s.target}", headers=s.headers,
                                      json={"first_name": "Changed"})
    assert response.status_code == 403, response.text
    assert s.snapshot() == before


async def test_member_can_update_bound_self_names(http_client, authority):
    s = authority
    revoke(s, "role_removed")
    s.claim_roles = []
    s.execute("UPDATE users SET sociacl_attributes=CAST(:attributes AS jsonb) WHERE id=:id",
              attributes='{"verification_level":2}', id=s.actor)
    response = await http_client.patch(f"/api/v1/users/{s.actor}", headers=s.headers,
                                      json={"first_name": "Self", "last_name": "Edited"})
    assert response.status_code == 200, response.text
    assert response.json()["first_name"] == "Self"
    assert response.json()["last_name"] == "Edited"
    assert response.json()["sociacl_attributes"] == {"verification_level": 2}


@pytest.mark.parametrize("reason", ["inactive", "deleted", "removed", "unbound", "tenant_inactive", "local_id_subject"])
async def test_self_edit_requires_active_subject_binding(http_client, authority, reason):
    s = authority
    revoke(s, reason)
    before = s.snapshot()
    response = await http_client.patch(f"/api/v1/users/{s.actor}", headers=s.headers,
                                      json={"first_name": "Changed"})
    assert response.status_code == 403, response.text
    assert s.snapshot() == before


@pytest.mark.parametrize("attributes", [
    {"verification_level": 4}, {"notes": "trusted"}, {"political_view": "other"}, None,
])
async def test_self_service_cannot_replace_trusted_sociacl(http_client, authority, attributes):
    s = authority
    revoke(s, "role_removed")
    before = s.snapshot()
    response = await http_client.patch(f"/api/v1/users/{s.actor}", headers=s.headers,
                                      json={"sociacl_attributes": attributes})
    assert response.status_code == 403, response.text
    assert s.snapshot() == before


async def test_admin_profile_edits_remain_tenant_scoped(http_client, authority):
    s = authority
    s.claim_roles = []
    response = await http_client.patch(f"/api/v1/users/{s.target}", headers=s.headers,
                                      json={"first_name": "Admin edit", "sociacl_attributes": {"verification_level": 2}})
    assert response.status_code == 200, response.text
    assert response.json()["first_name"] == "Admin edit"
    assert response.json()["sociacl_attributes"]["verification_level"] == 2
    foreign = await http_client.patch(f"/api/v1/users/{s.foreign_user}", headers=s.headers,
                                     json={"first_name": "Changed"})
    assert foreign.status_code == 404, foreign.text


async def test_admin_delete_cannot_target_foreign_tenant(http_client, authority):
    s = authority
    before = s.snapshot()
    response = await http_client.delete(f"/api/v1/users/{s.foreign_user}", headers=s.headers)
    assert response.status_code == 404, response.text
    assert s.snapshot() == before
