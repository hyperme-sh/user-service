"""Explicit additive migration for startup mappings in the User owner schema."""
import argparse
import hashlib
from importlib.resources import files
from pathlib import Path
from sqlalchemy import create_engine, text
from user_service.authority_migrate import install as install_authority


def install(engine, *, synthetic=False):
    if synthetic:
        from user_service.startup_github_fixture import require_test_owner
        with engine.connect() as db:
            require_test_owner(db)
    install_authority(engine)
    package = files('user_service')
    revisions = {
        '0003_startup': package.joinpath('startup_schema.sql').read_text(),
        '0004_startup_test_oidc': package.joinpath('startup_oidc_schema.sql').read_text(),
    }
    wanted = {name: hashlib.sha256(sql.encode()).hexdigest() for name, sql in revisions.items()}
    with engine.begin() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
        db.exec_driver_sql('CREATE TABLE IF NOT EXISTS owner_startup_version (revision text PRIMARY KEY, sha256 text NOT NULL)')
        current = dict(db.execute(text('SELECT revision,sha256 FROM owner_startup_version')).all())
        if (any(wanted.get(name) != digest for name, digest in current.items())
                or ('0004_startup_test_oidc' in current and '0003_startup' not in current)):
            raise ValueError('Startup schema identity differs')
        for name, sql in revisions.items():
            if name in current or (name == '0004_startup_test_oidc' and not synthetic):
                continue
            db.exec_driver_sql(sql)
            db.execute(text('INSERT INTO owner_startup_version VALUES (:revision,:digest)'),
                       {'revision': name, 'digest': wanted[name]})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url-file', type=Path, required=True)
    parser.add_argument('--synthetic', action='store_true')
    args = parser.parse_args()
    engine = create_engine(args.database_url_file.read_text().strip())
    try: install(engine, synthetic=args.synthetic)
    finally: engine.dispose()
