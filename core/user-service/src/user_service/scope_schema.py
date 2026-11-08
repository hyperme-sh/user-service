"""Explicit additive installation on an empty owner schema; never startup."""
import hashlib
from sqlalchemy import text

DDL_SHA256 = '339592b729f6f23e1b4b43aecd524fe791691b402562c7acb18c2b33eef6bda6'


def install(connection, ddl):
    if hashlib.sha256(ddl.encode()).hexdigest() != DDL_SHA256:
        raise ValueError('Scope schema digest differs')
    role=connection.execute(text("SELECT r.rolsuper,r.rolbypassrls,n.nspowner=r.oid AS owns_schema,n.nspname FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema() WHERE r.rolname=current_user")).mappings().one()
    if role['rolsuper'] or role['rolbypassrls'] or not role['owns_schema'] or role['nspname']=='public':
        raise ValueError('Scope schema requires a nonprivileged owner namespace')
    connection.exec_driver_sql("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))")
    exists=connection.scalar(text("SELECT to_regclass(current_schema() || '.identity_scope_schema')"))
    if exists:
        if connection.execute(text('SELECT revision,sha256 FROM identity_scope_schema')).all() != [('0002_scope_authority',DDL_SHA256)]:
            raise ValueError('Installed scope schema differs')
        return
    if connection.scalar(text("SELECT to_regclass(current_schema() || '.owner_schema_version')")) is None:
        raise ValueError('Fresh owner baseline required')
    # Never convert existing shared authorization data as an incidental test setup.
    for table in ('tenants','users','organizations'):
        if connection.scalar(text('SELECT EXISTS(SELECT 1 FROM '+table+')')):
            raise ValueError('Scope installation requires an empty declared generation')
    connection.exec_driver_sql(ddl)
    connection.execute(text('INSERT INTO identity_scope_schema VALUES(:revision,:digest)'),{'revision':'0002_scope_authority','digest':DDL_SHA256})
