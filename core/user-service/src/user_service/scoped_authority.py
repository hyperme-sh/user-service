"""Current, subject-bound User authority; role names and headers grant nothing."""

from contextlib import asynccontextmanager
import uuid
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


@asynccontextmanager
async def scope(session, tenant=None, network=None):
    previous = (
        await session.execute(
            text(
                "SELECT current_setting('app.current_tenant_id',true),current_setting('app.current_network_id',true)"
            )
        )
    ).one()
    await session.execute(
        text(
            "SELECT set_config('app.current_tenant_id',:tenant,true),set_config('app.current_network_id',:network,true)"
        ),
        {"tenant": str(tenant) if tenant else "", "network": network or ""},
    )
    failed = False
    try:
        yield
    except DBAPIError:
        # PostgreSQL has aborted this transaction. Its rollback restores LOCAL
        # settings; another SQL statement here would hide the original error.
        failed = True
        raise
    finally:
        if not failed:
            await session.execute(
                text(
                    "SELECT set_config('app.current_tenant_id',:tenant,true),set_config('app.current_network_id',:network,true)"
                ),
                {"tenant": previous[0] or "", "network": previous[1] or ""},
            )


async def identity_active(session, subject):
    if not subject:
        return False
    async with scope(session):
        return bool(
            await session.scalar(
                text(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id IS NULL AND keycloak_sub=:subject AND is_active AND deleted_at IS NULL)"
                ),
                {"subject": subject},
            )
        )


async def network_admin(session, network, subject):
    if not subject:
        return False
    async with scope(session, network=network):
        return bool(
            await session.scalar(
                text(
                    """SELECT EXISTS(SELECT 1 FROM authority_network_admins a
            JOIN authority_networks n ON n.id=a.network_id JOIN users u ON u.id=a.user_id
            WHERE a.network_id=:network AND a.enabled AND n.enabled AND u.tenant_id IS NULL
              AND u.is_active AND u.deleted_at IS NULL AND u.keycloak_sub=:subject)"""
                ),
                {"network": network, "subject": subject},
            )
        )


async def tenant_network(session, tenant):
    async with scope(session, tenant):
        return await session.scalar(
            text("SELECT network_id FROM authority_tenants WHERE tenant_id=:tenant"),
            {"tenant": tenant},
        )


async def active_tenant(session, tenant):
    network = await tenant_network(session, tenant)
    if not network:
        return False
    async with scope(session, tenant, network):
        return bool(
            await session.scalar(
                text(
                    """SELECT EXISTS(SELECT 1 FROM tenants t
            JOIN authority_tenants a ON a.tenant_id=t.id JOIN authority_networks n ON n.id=a.network_id
            WHERE t.id=:tenant AND t.is_active AND n.enabled)"""
                ),
                {"tenant": tenant},
            )
        )


async def actor_active(session, tenant, subject):
    """Recheck both identity IDs under the destination tenant's current bans."""
    if not await active_tenant(session, tenant):
        return False
    active = await identity_active(session, subject)
    if not active:
        from user_service.startup_identity import active_startup_person
        active = await active_startup_person(session, tenant, subject)
    if not active:
        return False
    from user_service.infrastructure.operator_store import active_ban

    async with scope(session):
        platform = await session.scalar(
            text(
                "SELECT id FROM users WHERE tenant_id IS NULL AND keycloak_sub=:subject"
            ),
            {"subject": subject},
        )
    async with scope(session, tenant):
        member = await session.scalar(
            text(
                "SELECT id FROM users WHERE tenant_id=:tenant AND keycloak_sub=:subject"
            ),
            {"tenant": tenant, "subject": subject},
        )
        for user_id in {platform, member} - {None}:
            if await active_ban(session, tenant, "user", user_id) is not None:
                return False
    return True


async def tenant_admin(session, tenant, subject):
    if not await actor_active(session, tenant, subject):
        return False
    network = await tenant_network(session, tenant)
    if network and await network_admin(session, network, subject):
        return True
    async with scope(session, tenant):
        return bool(
            await session.scalar(
                text(
                    """SELECT EXISTS(SELECT 1 FROM users u JOIN roles r ON r.id=u.role_id
            WHERE u.tenant_id=:tenant AND r.tenant_id=:tenant AND u.keycloak_sub=:subject
              AND u.is_active AND u.deleted_at IS NULL AND r.name='admin')"""
                ),
                {"tenant": tenant, "subject": subject},
            )
        )


async def organization_member(session, tenant, organization, subject):
    if not await actor_active(session, tenant, subject):
        return None
    async with scope(session, tenant):
        return (
            (
                await session.execute(
                    text(
                        """SELECT m.user_id,m.role,m.can_purchase_leases FROM organization_memberships m
            JOIN users u ON u.id=m.user_id AND u.tenant_id=m.tenant_id
            JOIN organizations o ON o.id=m.organization_id AND o.tenant_id=m.tenant_id
            WHERE m.tenant_id=:tenant AND m.organization_id=:organization AND m.enabled
              AND u.keycloak_sub=:subject AND u.is_active AND u.deleted_at IS NULL"""
                    ),
                    {
                        "tenant": tenant,
                        "organization": organization,
                        "subject": subject,
                    },
                )
            )
            .mappings()
            .one_or_none()
        )


async def allowed(
    session, *, subject, action, tenant=None, organization=None, network=None
):
    if action == "network.admin":
        return bool(
            network
            and tenant is None
            and organization is None
            and await network_admin(session, network, subject)
        )
    if (
        tenant is None
        or network is not None
        or not await active_tenant(session, tenant)
    ):
        return False
    if action in ("tenant.admin", "approval.resolve"):
        return organization is None and await tenant_admin(session, tenant, subject)
    if (
        action not in ("organization.read", "organization.admin", "lease.purchase")
        or organization is None
    ):
        return False
    async with scope(session, tenant):
        exists = await session.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM organizations WHERE id=:org AND tenant_id=:tenant)"
            ),
            {"org": organization, "tenant": tenant},
        )
    if not exists:
        return False
    # Network/tenant administration is not permission to spend an org's money.
    if action != "lease.purchase" and await tenant_admin(session, tenant, subject):
        return True
    member = await organization_member(session, tenant, organization, subject)
    if member is None:
        return False
    return (
        action == "organization.read"
        or (action == "organization.admin" and member["role"] == "admin")
        or (action == "lease.purchase" and member["can_purchase_leases"] is True)
    )


async def require(session, **query):
    if not await allowed(session, **query):
        raise HTTPException(403, "Authority is outside the current scope")


async def fixture_target(session, tenant, email):
    """Shared TEST accepts only the explicitly configured identity context."""
    import os

    if not os.environ.get("USER_TEST_FIXTURE_GENERATION"):
        return
    network = await tenant_network(session, tenant)
    async with scope(session, network=network):
        valid = await session.scalar(
            text(
                """SELECT EXISTS(SELECT 1 FROM authority_fixture_accounts f JOIN users u ON u.id=f.user_id
            WHERE f.tenant_context=:tenant AND f.network_id=:network AND lower(u.email)=lower(:email)
              AND u.tenant_id IS NULL AND u.is_active AND u.deleted_at IS NULL)"""
            ),
            {"tenant": tenant, "network": network, "email": email},
        )
    if not valid:
        raise HTTPException(403, "Identity is outside the configured TEST fixtures")


async def host_scope(session, tenant, subject):
    if not await actor_active(session, tenant, subject):
        return None
    async with scope(session, tenant):
        return (
            (
                await session.execute(
                    text(
                        """SELECT h.user_id,h.organization_id
            FROM authority_host_owners h JOIN organization_memberships m
            USING(tenant_id,organization_id,user_id)
            JOIN users u ON u.id=h.user_id AND u.tenant_id=h.tenant_id
            WHERE h.tenant_id=:tenant AND m.enabled AND u.is_active
              AND u.deleted_at IS NULL AND u.keycloak_sub=:subject"""
                    ),
                    {"tenant": tenant, "subject": subject},
                )
            )
            .mappings()
            .one_or_none()
        )


async def billing_member(session, tenant, subject):
    """A current org billing grant, independent of cached portal groups."""
    if not await actor_active(session, tenant, subject):
        return False
    from user_service.infrastructure.operator_store import active_ban

    async with scope(session, tenant):
        user = await session.scalar(
            text(
                """SELECT u.id FROM users u
            WHERE u.tenant_id=:tenant AND u.keycloak_sub=:subject AND u.is_active
            AND u.deleted_at IS NULL AND EXISTS(SELECT 1 FROM organization_memberships m
              WHERE m.tenant_id=u.tenant_id AND m.user_id=u.id AND m.enabled AND m.can_purchase_leases)"""
            ),
            {"tenant": tenant, "subject": subject},
        )
        return (
            user is not None and await active_ban(session, tenant, "user", user) is None
        )
