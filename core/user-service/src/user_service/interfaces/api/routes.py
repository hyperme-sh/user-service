from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.common.event_types import (
    GROUP_MEMBER_ADDED_V1,
    GROUP_MEMBER_REMOVED_V1,
    USER_CREATED_V1,
)
from api.common.portal_controls import PortalControls, evaluate_portal_controls
from api.infrastructure.messaging.tenant_event_publisher import get_tenant_event_publisher
from api.infrastructure.persistence.db_session import get_db_session
from auth_service.schemas import AuthMeResponse
from controlplane_events.payloads import (
    GroupMemberAddedPayload,
    GroupMemberRemovedPayload,
    UserCreatedEvent,
)

from user_service.deps import get_current_user, require_matched_tenant
from user_service.domain.dtos import (
    GroupCreateBody,
    GroupListPage,
    GroupMemberListPage,
    GroupMemberResponse,
    GroupResponse,
    OrganizationCreateBody,
    OrganizationIdpLinkCreateBody,
    OrganizationIdpLinkList,
    OrganizationIdpLinkResponse,
    OrganizationListPage,
    OrganizationResponse,
    PortalControlsResponse,
    UserCreateBody,
    UserListPage,
    UserResponse,
    UserRoleUpdateBody,
    UserUpdateBody,
)
from user_service.idp_links import PROVIDERS, normalize_external_key, proof_failure
from user_service.infrastructure.persistence.repos import (
    SqlGroupRepository,
    SqlMembershipRepository,
    SqlOrganizationIdpLinkRepository,
    SqlOrganizationRepository,
    SqlRoleRepository,
    SqlUserRepository,
)

router = APIRouter(tags=["Users & groups"])


def _user_to_response(u) -> UserResponse:
    if u.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not tenant-scoped",
        )
    return UserResponse(
        id=u.id,
        tenant_id=u.tenant_id,
        email=u.email,
        first_name=u.first_name,
        last_name=u.last_name,
        gender=u.gender,
        is_active=u.is_active,
        deleted_at=u.deleted_at,
        sociacl_attributes=u.sociacl_attributes,
        role_id=u.role_id,
    )


def _actor_sub_as_uuid(me: AuthMeResponse) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(me.sub))
    except (ValueError, TypeError):
        return None


async def _lookup_actor_user(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    me: AuthMeResponse,
):
    urepo = SqlUserRepository(session)
    sub_uuid = _actor_sub_as_uuid(me)
    if sub_uuid is not None:
        user = await urepo.get(tenant_id, sub_uuid)
        if user is not None:
            return user
    if me.sub:
        user = await urepo.get_by_keycloak_sub(tenant_id, me.sub)
        if user is not None:
            return user
    if me.email:
        return await urepo.get_by_email(tenant_id, me.email)
    return None


async def actor_portal_controls(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    me: AuthMeResponse,
) -> PortalControls:
    roles = list(me.roles)
    groups = list(me.groups)
    user = await _lookup_actor_user(session, tenant_id, me)
    if user is not None:
        if user.role_id is not None:
            role = await SqlRoleRepository(session).get(tenant_id, user.role_id)
            if role is not None:
                roles.append(role.name)
        for group in await SqlMembershipRepository(session).groups_for_user(
            tenant_id, user.id
        ):
            groups.append(group.name)
    return evaluate_portal_controls(roles, groups)


def _require_flag(controls: PortalControls, flag: str, detail: str) -> None:
    if not getattr(controls, flag):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def create_user(
    body: UserCreateBody,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    # Invite only. Enrollment does not self-join through this HTTP door.
    controls = await actor_portal_controls(session, tenant_id, me)
    _require_flag(
        controls,
        "can_invite_members",
        "Org admin role required to invite members",
    )
    repo = SqlUserRepository(session)
    u = await repo.create(tenant_id, body)
    display = f"{u.first_name} {u.last_name}".strip()
    await get_tenant_event_publisher().publish(
        tenant_id=tenant_id,
        event_type=USER_CREATED_V1,
        payload=UserCreatedEvent(
            user_id=u.id,
            email=u.email,
            tenant_id=str(tenant_id),
            display_name=display or None,
        ).to_envelope_payload(),
    )
    return _user_to_response(u)


@router.get(
    "/users",
    response_model=UserListPage,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_users(
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    q: str | None = Query(
        None,
        max_length=256,
        description="Case-insensitive search on email, first name, or last name",
    ),
):
    repo = SqlUserRepository(session)
    users, total = await repo.list_active_paged(
        tenant_id, offset=offset, limit=limit, q=q
    )
    return UserListPage(
        items=[_user_to_response(u) for u in users],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.patch(
    "/users/{user_id}",
    response_model=UserResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdateBody,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    repo = SqlUserRepository(session)
    u = await repo.update(tenant_id, user_id, body)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return _user_to_response(u)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def delete_user(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    controls = await actor_portal_controls(session, tenant_id, me)
    _require_flag(
        controls,
        "can_invite_members",
        "Org admin role required to remove members",
    )
    repo = SqlUserRepository(session)
    ok = await repo.soft_delete(tenant_id, user_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")


@router.post(
    "/groups",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def create_group(
    body: GroupCreateBody,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    repo = SqlGroupRepository(session)
    g = await repo.create(tenant_id, body.name, body.description, body.role_id)
    return GroupResponse.model_validate(g)


@router.get(
    "/groups",
    response_model=GroupListPage,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_groups(
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    q: str | None = Query(
        None,
        max_length=256,
        description="Case-insensitive search on name or description",
    ),
):
    repo = SqlGroupRepository(session)
    groups, total = await repo.list_paged(
        tenant_id, offset=offset, limit=limit, q=q
    )
    return GroupListPage(
        items=[GroupResponse.model_validate(g) for g in groups],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/groups/{group_id}",
    response_model=GroupResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def get_group(
    group_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    repo = SqlGroupRepository(session)
    g = await repo.get(tenant_id, group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")
    return GroupResponse.model_validate(g)


def _require_org_admin(me: AuthMeResponse) -> None:
    controls = evaluate_portal_controls(me.roles, me.groups)
    if not controls.org_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organization admin required")


def _link_response(link) -> OrganizationIdpLinkResponse:
    return OrganizationIdpLinkResponse(
        id=link.id,
        tenant_id=link.tenant_id,
        organization_id=link.organization_id,
        provider=link.provider,
        external_key=link.external_key,
    )


@router.get(
    "/organizations/idp-match",
    response_model=OrganizationIdpLinkResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def match_organization_for_sign_in(
    me: AuthMeResponse = Depends(get_current_user),
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
) -> OrganizationIdpLinkResponse:
    """Enterprise this sign-in's identity-provider org is linked to."""
    if me.idp_account != "organization" or not me.idp_provider or not me.idp_org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No organization on this sign-in")
    key = normalize_external_key(me.idp_provider, me.idp_org)
    link = await SqlOrganizationIdpLinkRepository(session).find(tenant_id, me.idp_provider, key)
    if link is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No enterprise link for this sign-in")
    return _link_response(link)


@router.get(
    "/organizations/{organization_id}/idp-links",
    response_model=OrganizationIdpLinkList,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_organization_idp_links(
    organization_id: uuid.UUID,
    me: AuthMeResponse = Depends(get_current_user),
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
) -> OrganizationIdpLinkList:
    _require_org_admin(me)
    org = await SqlOrganizationRepository(session).get(tenant_id, organization_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    rows = await SqlOrganizationIdpLinkRepository(session).list_for_org(tenant_id, organization_id)
    return OrganizationIdpLinkList(items=[_link_response(row) for row in rows])


@router.post(
    "/organizations/{organization_id}/idp-links",
    response_model=OrganizationIdpLinkResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def link_organization_idp(
    organization_id: uuid.UUID,
    body: OrganizationIdpLinkCreateBody,
    me: AuthMeResponse = Depends(get_current_user),
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
) -> OrganizationIdpLinkResponse:
    """Save an IdP org on this enterprise after the owner proves they administer it."""
    _require_org_admin(me)
    provider = body.provider.strip().lower()
    if provider not in PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unknown identity provider",
        )
    key = normalize_external_key(provider, body.external_key)
    reason = proof_failure(
        provider=provider,
        external_key=key,
        idp_provider=me.idp_provider,
        idp_org=me.idp_org,
        idp_orgs=me.idp_orgs,
        idp_wids=me.idp_wids,
    )
    if reason:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
    org = await SqlOrganizationRepository(session).get(tenant_id, organization_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    repo = SqlOrganizationIdpLinkRepository(session)
    existing = await repo.find(tenant_id, provider, key)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That identity-provider organization is already linked",
        )
    try:
        link = await repo.create(
            tenant_id=tenant_id,
            organization_id=organization_id,
            provider=provider,
            external_key=key,
            linked_by_sub=me.sub,
        )
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That identity-provider organization is already linked",
        ) from None
    return _link_response(link)


@router.delete(
    "/organizations/{organization_id}/idp-links/{link_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def unlink_organization_idp(
    organization_id: uuid.UUID,
    link_id: uuid.UUID,
    me: AuthMeResponse = Depends(get_current_user),
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    _require_org_admin(me)
    deleted = await SqlOrganizationIdpLinkRepository(session).delete(
        tenant_id, organization_id, link_id
    )
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")


@router.post(
    "/organizations",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def create_organization(
    body: OrganizationCreateBody,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    repo = SqlOrganizationRepository(session)
    o = await repo.create(tenant_id, body.legal_name)
    return OrganizationResponse.model_validate(o)


@router.get(
    "/organizations",
    response_model=OrganizationListPage,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_organizations(
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    q: str | None = Query(
        None,
        max_length=256,
        description="Case-insensitive search on legal name",
    ),
):
    repo = SqlOrganizationRepository(session)
    orgs, total = await repo.list_paged(
        tenant_id, offset=offset, limit=limit, q=q
    )
    return OrganizationListPage(
        items=[OrganizationResponse.model_validate(o) for o in orgs],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/organizations/{organization_id}",
    response_model=OrganizationResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def get_organization(
    organization_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    repo = SqlOrganizationRepository(session)
    o = await repo.get(tenant_id, organization_id)
    if o is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return OrganizationResponse.model_validate(o)


@router.patch(
    "/users/{user_id}/assign_role",
    response_model=UserResponse,
    status_code=status.HTTP_202_ACCEPTED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def assign_user_role(
    user_id: uuid.UUID,
    body: UserRoleUpdateBody,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    urepo = SqlUserRepository(session)
    rrepo = SqlRoleRepository(session)
    user = await urepo.get(tenant_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    role = await rrepo.get(tenant_id, body.role_id)
    if role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Role not found")
    if user.role_id == body.role_id:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "User already has this role assigned"
        )
    updated = await urepo.set_role(tenant_id, user_id, body.role_id)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return _user_to_response(updated)


@router.patch(
    "/users/{user_id}/remove_role",
    response_model=UserResponse,
    status_code=status.HTTP_202_ACCEPTED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def remove_user_role(
    user_id: uuid.UUID,
    body: UserRoleUpdateBody,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    urepo = SqlUserRepository(session)
    user = await urepo.get(tenant_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.role_id != body.role_id:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "User does not have this role assigned"
        )
    updated = await urepo.set_role(tenant_id, user_id, None)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return _user_to_response(updated)


@router.post(
    "/users/{user_id}/groups/{group_id}",
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def add_user_to_group(
    user_id: uuid.UUID,
    group_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    controls = await actor_portal_controls(session, tenant_id, me)
    _require_flag(
        controls,
        "can_assign_group",
        "Org admin role required to assign groups",
    )
    urepo = SqlUserRepository(session)
    grep = SqlGroupRepository(session)
    mrepo = SqlMembershipRepository(session)
    user = await urepo.get(tenant_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    group = await grep.get(tenant_id, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")
    if await mrepo.exists(tenant_id, user_id, group_id):
        raise HTTPException(status.HTTP_409_CONFLICT, "User already in group")
    try:
        m = await mrepo.add(tenant_id, user_id, group_id)
    except IntegrityError as e:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Could not add membership"
        ) from e
    await get_tenant_event_publisher().publish(
        tenant_id=tenant_id,
        event_type=GROUP_MEMBER_ADDED_V1,
        payload=GroupMemberAddedPayload(
            user_id=user_id,
            group_id=group_id,
            tenant_id=tenant_id,
            added_by_user_id=_actor_sub_as_uuid(me),
        ).to_envelope_payload(),
    )
    return {"id": str(m.id)}


@router.delete(
    "/users/{user_id}/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def remove_user_from_group(
    user_id: uuid.UUID,
    group_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    controls = await actor_portal_controls(session, tenant_id, me)
    _require_flag(
        controls,
        "can_assign_group",
        "Org admin role required to assign groups",
    )
    urepo = SqlUserRepository(session)
    grep = SqlGroupRepository(session)
    mrepo = SqlMembershipRepository(session)
    user = await urepo.get(tenant_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    group = await grep.get(tenant_id, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")
    ok = await mrepo.remove(tenant_id, user_id, group_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    await get_tenant_event_publisher().publish(
        tenant_id=tenant_id,
        event_type=GROUP_MEMBER_REMOVED_V1,
        payload=GroupMemberRemovedPayload(
            user_id=user_id,
            group_id=group_id,
            tenant_id=tenant_id,
            removed_by_user_id=_actor_sub_as_uuid(me),
        ).to_envelope_payload(),
    )


@router.get(
    "/groups/{group_id}/members",
    response_model=GroupMemberListPage,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_group_members(
    group_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    grep = SqlGroupRepository(session)
    group = await grep.get(tenant_id, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")
    rows = await SqlMembershipRepository(session).list_for_group(tenant_id, group_id)
    sliced = rows[offset : offset + limit]
    items = [
        GroupMemberResponse(
            user_id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            role_id=user.role_id,
            group_id=group.id,
            group_name=group.name,
        )
        for _membership, user in sliced
    ]
    return GroupMemberListPage(
        items=items, total=len(rows), limit=limit, offset=offset
    )


@router.get(
    "/users/{user_id}/groups",
    response_model=GroupListPage,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def list_user_groups(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    urepo = SqlUserRepository(session)
    user = await urepo.get(tenant_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    groups = await SqlMembershipRepository(session).groups_for_user(tenant_id, user_id)
    return GroupListPage(
        items=[GroupResponse.model_validate(g) for g in groups],
        total=len(groups),
        limit=len(groups) or 1,
        offset=0,
    )


@router.get(
    "/me/portal-controls",
    response_model=PortalControlsResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def get_portal_controls(
    tenant_id: uuid.UUID = Depends(require_matched_tenant),
    me: AuthMeResponse = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
):
    controls = await actor_portal_controls(session, tenant_id, me)
    return PortalControlsResponse.model_validate(controls.as_dict())
