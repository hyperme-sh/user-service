-- Key writers need no direct write access to the owner's global tenant mirror.
CREATE FUNCTION api_key_remember_tenant() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO pg_catalog, __OWNER_SCHEMA__, pg_temp
AS $$
BEGIN
    IF current_setting('app.skip_tenant_remember',true)='1' THEN RETURN NEW; END IF;
    IF NEW.tenant_id IS NULL OR NEW.tenant_id::text IS DISTINCT FROM
       nullif(current_setting('app.current_tenant_id',true),'') THEN
        RAISE EXCEPTION 'Current key tenant required' USING ERRCODE='42501';
    END IF;
    INSERT INTO __OWNER_SCHEMA__.service_tenants(tenant_id) VALUES(NEW.tenant_id) ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION api_key_remember_tenant() FROM PUBLIC;
DROP TRIGGER remember_tenant ON api_keys;
CREATE TRIGGER remember_tenant AFTER INSERT OR UPDATE OF tenant_id ON api_keys
FOR EACH ROW EXECUTE FUNCTION api_key_remember_tenant();
