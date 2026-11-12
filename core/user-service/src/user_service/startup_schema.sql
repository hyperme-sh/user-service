-- Explicit owner migration; application startup never creates schema.
CREATE TABLE startup_identity_bindings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    user_id uuid NOT NULL UNIQUE,
    entra_tenant_id uuid NOT NULL,
    entra_account_id uuid NOT NULL,
    mapping_sha256 text NOT NULL CHECK(mapping_sha256 ~ '^[a-f0-9]{64}$'),
    sea_public_key text NOT NULL,
    broker_subject text UNIQUE,
    UNIQUE(entra_tenant_id,entra_account_id),
    FOREIGN KEY(user_id,tenant_id) REFERENCES users(id,tenant_id)
);
CREATE TABLE startup_organizations (
    tenant_id uuid NOT NULL,
    slug text NOT NULL CHECK(slug IN ('fyberlabs','tennesseewindage','hyperme.sh')),
    organization_id uuid NOT NULL UNIQUE,
    PRIMARY KEY(tenant_id,slug),
    FOREIGN KEY(organization_id,tenant_id) REFERENCES organizations(id,tenant_id)
);
CREATE TABLE startup_organization_owners (
    tenant_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    PRIMARY KEY(tenant_id,organization_id,user_id),
    FOREIGN KEY(tenant_id,organization_id,user_id)
        REFERENCES organization_memberships(tenant_id,organization_id,user_id)
);
ALTER TABLE startup_identity_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE startup_identity_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY startup_tenant ON startup_identity_bindings
    USING (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''))
    WITH CHECK (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''));
ALTER TABLE startup_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE startup_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY startup_tenant ON startup_organizations
    USING (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''))
    WITH CHECK (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''));
ALTER TABLE startup_organization_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE startup_organization_owners FORCE ROW LEVEL SECURITY;
CREATE POLICY startup_tenant ON startup_organization_owners
    USING (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''))
    WITH CHECK (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''));
