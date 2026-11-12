"""Explicit additive migration for startup mappings in the User owner schema."""
import argparse
import hashlib
from importlib.resources import files
from pathlib import Path
from sqlalchemy import create_engine, text
from user_service.authority_migrate import install as install_authority


def install(engine):
    # Reuse the owner/migrator separation and immutable baseline checks.
    install_authority(engine)
    ddl = files('user_service').joinpath('startup_schema.sql').read_text()
    digest = hashlib.sha256(ddl.encode()).hexdigest()
    with engine.begin() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))"))
        db.exec_driver_sql('CREATE TABLE IF NOT EXISTS owner_startup_version (revision text PRIMARY KEY, sha256 text NOT NULL)')
        rows = db.execute(text('SELECT revision,sha256 FROM owner_startup_version')).all()
        if rows:
            if rows != [('0003_startup', digest)]: raise ValueError('Startup schema identity differs')
            return
        db.exec_driver_sql(ddl)
        db.execute(text('INSERT INTO owner_startup_version VALUES (:revision,:digest)'),
                   {'revision':'0003_startup','digest':digest})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url-file', type=Path, required=True)
    args = parser.parse_args()
    engine = create_engine(args.database_url_file.read_text().strip())
    try: install(engine)
    finally: engine.dispose()
