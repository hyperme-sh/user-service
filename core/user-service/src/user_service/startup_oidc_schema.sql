-- Explicit TEST-only extension to the existing startup identity table.
ALTER TABLE startup_identity_bindings
    ALTER COLUMN entra_tenant_id DROP NOT NULL,
    ALTER COLUMN entra_account_id DROP NOT NULL,
    ADD COLUMN oidc_upstream_subject uuid UNIQUE,
    ADD CONSTRAINT startup_identity_provider_tuple CHECK (
        (entra_tenant_id IS NOT NULL AND entra_account_id IS NOT NULL AND oidc_upstream_subject IS NULL)
        OR
        (entra_tenant_id IS NULL AND entra_account_id IS NULL AND oidc_upstream_subject IS NOT NULL)
    );
