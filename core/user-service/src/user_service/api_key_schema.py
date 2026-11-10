"""Explicit additive API-key schema installation by the existing User DB owner.

No application startup migration, fixture creation or runtime-role grants.
"""
import argparse
import hashlib
from importlib.resources import files
from pathlib import Path

from sqlalchemy import create_engine, text

BASELINE = '440fb48049959f5b3a8338ec0ba21e32b91e6ec23628e5bcc7191092b12b2e03'
REVISION = '0001_api_key_authority'


def install(engine):
    ddl=files('user_service').joinpath('api_key_schema.sql').read_text()
    digest=hashlib.sha256(ddl.encode()).hexdigest()
    with engine.begin() as db:
        row=db.execute(text('''SELECT n.nspname,n.nspowner=r.oid AS owner,
            r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication
            FROM pg_roles r JOIN pg_namespace n ON n.nspname=current_schema()
            WHERE r.rolname=current_user''')).mappings().one()
        if not row['owner'] or row['nspname'] in ('public','pg_catalog') or any(
            row[k] for k in ('rolsuper','rolbypassrls','rolcreaterole','rolcreatedb','rolreplication')
        ):raise ValueError('Nonprivileged User schema owner required')
        db.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))'))
        if db.execute(text('SELECT revision,sha256 FROM owner_schema_version')).all()!=[
            ('0001_owner_schema',BASELINE)
        ]:raise ValueError('Immutable User baseline differs')
        if db.scalar(text("SELECT to_regclass(current_schema()||'.owner_authority_version')")) is None:
            raise ValueError('Install the declared authority contract first')
        db.exec_driver_sql('CREATE TABLE IF NOT EXISTS api_key_schema_version(revision text PRIMARY KEY,sha256 text NOT NULL)')
        previous=db.execute(text('SELECT revision,sha256 FROM api_key_schema_version')).all()
        if previous:
            if previous!=[(REVISION,digest)]:raise ValueError('API key schema identity differs')
            return
        # The authority owner already declares the organization/tenant constraint.
        # SQL identifiers come exclusively from the verified owner namespace.
        schema=engine.dialect.identifier_preparer.quote_identifier(row['nspname'])
        db.exec_driver_sql(ddl.replace('__OWNER_SCHEMA__',schema))
        db.execute(text('INSERT INTO api_key_schema_version VALUES(:revision,:digest)'),
                   {'revision':REVISION,'digest':digest})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url-file',type=Path,required=True)
    args=parser.parse_args()
    engine=create_engine(args.database_url_file.read_text().strip())
    try:install(engine)
    finally:engine.dispose()
