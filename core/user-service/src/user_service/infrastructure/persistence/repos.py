"""HTTP DTO adapters for the platform directory owner contract."""
from controlplane_tenancy.directory import (
    SqlUserRepository as _OwnerUsers,
    SqlRoleRepository,
    SqlGroupRepository as _OwnerGroups,
    SqlOrganizationRepository,
    SqlOrganizationIdpLinkRepository,
    SqlMembershipRepository,
    DirectoryLinkError,
    UserCreateData,
    UserUpdateData,
)


class SqlUserRepository(_OwnerUsers):
    async def create(self, tenant_id, body):
        return await super().create(tenant_id, UserCreateData(
            email=str(body.email), first_name=body.first_name,
            last_name=body.last_name, gender=body.gender, is_active=body.is_active,
        ))

    async def set_role(self, tenant_id, user_id, role_id):
        from fastapi import HTTPException
        try:
            return await super().set_role(tenant_id, user_id, role_id)
        except DirectoryLinkError:
            raise HTTPException(404, "Role not found") from None

    async def update(self, tenant_id, user_id, body):
        attributes = body.sociacl_attributes
        return await super().update(tenant_id, user_id, UserUpdateData(
            first_name=body.first_name, last_name=body.last_name,
            sociacl_attributes=attributes.model_dump(mode="json") if attributes is not None else None,
        ))


class SqlGroupRepository(_OwnerGroups):
    async def create(self, tenant_id, name, description, role_id):
        from fastapi import HTTPException
        try:
            return await super().create(tenant_id, name, description, role_id)
        except DirectoryLinkError:
            raise HTTPException(404, "Role not found") from None
