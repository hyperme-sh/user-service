"""Scoped person and organization reconciliation; callers own the transaction."""
import uuid
from sqlalchemy import text
from user_service._startup_contract import validate, fingerprint
from controlplane_tenancy.tenant_guc import set_current_tenant_id_guc


class StartupConflict(ValueError):
    pass


def external_key(config):
    return 'entra:' + config['entra_tenant_id'] + ':' + config['entra_account_id']


def person_plan(config, binding, people):
    """Pure conflict rules; email detects conflicts but never selects an identity."""
    validate(config)
    if binding and binding['mapping_sha256'] != fingerprint(config):
        raise StartupConflict('Configured startup mapping differs')
    if len(people) > 1: raise StartupConflict('Multiple person bindings conflict')
    person = people[0] if people else None
    if person:
        if (person['sso_provider_id'] != external_key(config) or not person['is_active'] or person['deleted_at'] is not None or
                person['email'].lower() != config['email'].lower()):
            raise StartupConflict('Person ' + str(person['id']) + ' conflicts with configured external_binding')
        if binding and str(binding['user_id']) != str(person['id']):
            raise StartupConflict('Configured person differs from stored mapping')
    elif binding:
        raise StartupConflict('Configured person is missing')
    return person


async def one(db, sql, parameters):
    return (await db.execute(text(sql), parameters)).mappings().one_or_none()


async def prepare_scope(db, config):
    validate(config)
    tenant = uuid.UUID(config['tenant_id'])
    await set_current_tenant_id_guc(db, tenant)
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                     {'key':'startup-user:' + str(tenant)})
    active = await db.scalar(text('SELECT EXISTS(SELECT 1 FROM tenants WHERE id=:tenant AND is_active)'), {'tenant':tenant})
    network = await db.scalar(text('SELECT network_id FROM authority_tenants WHERE tenant_id=:tenant'), {'tenant':tenant})
    if not active or network != config['network_id']:
        raise StartupConflict('Configured tenant/network is unavailable')
    return tenant


async def reconcile(db, config):
    tenant = await prepare_scope(db, config)
    params = {'tenant':tenant, 'external':external_key(config), 'email':config['email'].lower()}
    binding = await one(db, 'SELECT * FROM startup_identity_bindings WHERE tenant_id=:tenant FOR UPDATE', params)
    people = (await db.execute(text('''SELECT id,email,sso_provider_id,is_active,deleted_at,keycloak_sub
        FROM users WHERE tenant_id=:tenant AND (lower(email)=:email OR sso_provider_id=:external) FOR UPDATE'''), params)).mappings().all()
    person = person_plan(config, binding, people)
    if person is None:
        params['user'] = uuid.uuid4()
        await db.execute(text('''INSERT INTO users (id,tenant_id,first_name,last_name,email,gender,is_active,sso_provider_id)
            VALUES (:user,:tenant,'Configured','Operator',:email,'unspecified',true,:external)'''), params)
        subject = None
    else:
        params['user'] = person['id']
        subject = person['keycloak_sub']
    if binding is None:
        await db.execute(text('''INSERT INTO startup_identity_bindings
            (tenant_id,user_id,entra_tenant_id,entra_account_id,mapping_sha256,sea_public_key,broker_subject)
            VALUES (:tenant,:user,:entra_tenant,:entra_account,:mapping,:sea,:subject)'''),
            {**params, 'entra_tenant':uuid.UUID(config['entra_tenant_id']), 'entra_account':uuid.UUID(config['entra_account_id']),
             'mapping':fingerprint(config), 'sea':config['sea_public_key'], 'subject':subject})
    elif binding['broker_subject'] != subject:
        raise StartupConflict('Stored broker subject differs from person')
    organizations = []
    for slug in config['organizations']:
        params['slug'] = slug
        existing = await one(db, '''SELECT o.id,o.legal_name FROM startup_organizations s JOIN organizations o
            ON o.id=s.organization_id AND o.tenant_id=s.tenant_id WHERE s.tenant_id=:tenant AND s.slug=:slug''', params)
        if existing is None:
            if binding is not None: raise StartupConflict('Stored startup organization is missing')
            conflict = await db.scalar(text('SELECT id FROM organizations WHERE tenant_id=:tenant AND legal_name=:slug'), params)
            if conflict: raise StartupConflict('Organization ' + str(conflict) + ' has no matching startup binding')
            params['org'] = uuid.uuid4()
            await db.execute(text('INSERT INTO organizations(id,tenant_id,legal_name) VALUES (:org,:tenant,:slug)'), params)
            await db.execute(text('INSERT INTO startup_organizations VALUES (:tenant,:slug,:org)'), params)
            await db.execute(text("INSERT INTO organization_memberships(tenant_id,organization_id,user_id,role) VALUES (:tenant,:org,:user,'admin')"), params)
            await db.execute(text('INSERT INTO startup_organization_owners VALUES (:tenant,:org,:user)'), params)
        else:
            if existing['legal_name'] != slug: raise StartupConflict('Startup organization label differs')
            params['org'] = existing['id']
            member = await one(db, '''SELECT m.role,m.enabled,EXISTS(SELECT 1 FROM startup_organization_owners o
                WHERE o.tenant_id=m.tenant_id AND o.organization_id=m.organization_id AND o.user_id=m.user_id) AS owner
                FROM organization_memberships m WHERE m.tenant_id=:tenant AND m.organization_id=:org AND m.user_id=:user''', params)
            if not member or member['role'] != 'admin' or not member['enabled'] or not member['owner']:
                raise StartupConflict('Startup membership differs from configured owner/admin grants')
        organizations.append({'slug':slug, 'id':str(params['org']), 'roles':['owner','admin']})
    return {'schema_version':1, 'mapping_sha256':fingerprint(config), 'person_id':str(params['user']),
            'tenant_id':str(tenant), 'network_id':config['network_id'], 'organizations':organizations,
            'broker_subject':subject, 'status':'reconciled'}


async def bind_broker(db, config, subject):
    tenant = await prepare_scope(db, config)
    binding = await one(db, 'SELECT * FROM startup_identity_bindings WHERE tenant_id=:tenant FOR UPDATE', {'tenant':tenant})
    if not binding or binding['mapping_sha256'] != fingerprint(config):
        raise StartupConflict('Reconciled person required before broker binding')
    # Auth may establish only the chosen opaque person subject; existing subjects
    # are preserved, never replaced through a replay or email match.
    expected = binding['broker_subject'] or str(binding['user_id'])
    if subject != expected: raise StartupConflict('Broker subject conflicts with configured person')
    person = await one(db, 'SELECT keycloak_sub FROM users WHERE id=:user AND tenant_id=:tenant FOR UPDATE',
                       {'user':binding['user_id'],'tenant':tenant})
    if not person or person['keycloak_sub'] not in (None,subject):
        raise StartupConflict('Person broker link conflicts')
    await db.execute(text('UPDATE users SET keycloak_sub=:subject WHERE id=:user AND tenant_id=:tenant'),
                     {'subject':subject,'user':binding['user_id'],'tenant':tenant})
    await db.execute(text('UPDATE startup_identity_bindings SET broker_subject=:subject WHERE tenant_id=:tenant'),
                     {'subject':subject,'tenant':tenant})
    return {'schema_version':1, 'mapping_sha256':fingerprint(config), 'person_id':str(binding['user_id']),
            'broker_subject':subject, 'status':'bound'}
