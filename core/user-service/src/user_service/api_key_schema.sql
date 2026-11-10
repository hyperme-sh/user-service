-- Additive key-owner contract. Never import identities or rewrite the baseline.
ALTER TABLE api_keys ADD CONSTRAINT api_key_id_tenant UNIQUE (id,tenant_id);
CREATE TABLE api_key_authority_bindings (
    key_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    organization_id uuid,
    network_id text NOT NULL CHECK(length(network_id) BETWEEN 1 AND 255),
    scope_kind text NOT NULL CHECK(scope_kind IN ('organization','network')),
    owner_sub varchar(512) NOT NULL CHECK(length(owner_sub)>0),
    FOREIGN KEY(key_id,tenant_id) REFERENCES api_keys(id,tenant_id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,tenant_id) REFERENCES organizations(id,tenant_id),
    CHECK ((scope_kind='organization')=(organization_id IS NOT NULL))
);
CREATE INDEX api_key_authority_owner ON api_key_authority_bindings(tenant_id,organization_id,owner_sub);
ALTER TABLE api_key_authority_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_key_authority_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_tenant ON api_key_authority_bindings
    USING(tenant_id::text=NULLIF(current_setting('app.current_tenant_id',true),''))
    WITH CHECK(tenant_id::text=NULLIF(current_setting('app.current_tenant_id',true),''));
CREATE TABLE api_key_owner_closures (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    subject varchar(512) NOT NULL CHECK(length(subject)>0),
    closed_at timestamptz NOT NULL,
    PRIMARY KEY(tenant_id,subject)
);
ALTER TABLE api_key_owner_closures ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_key_owner_closures FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_tenant ON api_key_owner_closures
    USING(tenant_id::text=NULLIF(current_setting('app.current_tenant_id',true),''))
    WITH CHECK(tenant_id::text=NULLIF(current_setting('app.current_tenant_id',true),''));

-- The private closure receiver must discover exact-subject credentials even if
-- directory membership is gone. Iterate declared tenants under ordinary RLS;
-- expose only metadata, never hashes/secrets, and restore the caller's context.
CREATE FUNCTION api_key_subject_inventory(wanted_subject text)
RETURNS TABLE(id uuid,tenant_id uuid,key_fingerprint varchar(64),purpose varchar(32))
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO pg_catalog, __OWNER_SCHEMA__
AS $$
DECLARE selected_tenant uuid; previous_tenant text; emitted integer:=0; added integer;
BEGIN
    IF wanted_subject IS NULL OR length(wanted_subject) NOT BETWEEN 1 AND 512
       OR wanted_subject LIKE 'apikey:%' THEN
        RAISE EXCEPTION 'Exact account subject required';
    END IF;
    previous_tenant:=COALESCE(current_setting('app.current_tenant_id',true),'');
    BEGIN
        FOR selected_tenant IN SELECT t.id FROM tenants t ORDER BY t.id LOOP
            PERFORM set_config('app.current_tenant_id',selected_tenant::text,true);
            RETURN QUERY SELECT k.id,k.tenant_id,k.key_fingerprint,k.purpose
                FROM api_keys k WHERE k.tenant_id=selected_tenant AND k.created_by_sub=wanted_subject
                ORDER BY k.id LIMIT 100001-emitted;
            GET DIAGNOSTICS added=ROW_COUNT;
            emitted:=emitted+added;
            IF emitted>100000 THEN RAISE EXCEPTION 'Account key inventory exceeds limit'; END IF;
        END LOOP;
        PERFORM set_config('app.current_tenant_id',previous_tenant,true);
    EXCEPTION WHEN OTHERS THEN
        PERFORM set_config('app.current_tenant_id',previous_tenant,true);
        RAISE;
    END;
END;
$$;
REVOKE ALL ON FUNCTION api_key_subject_inventory(text) FROM PUBLIC;
