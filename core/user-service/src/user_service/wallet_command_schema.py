"""Explicit additive installation by the User schema owner."""
import argparse
from pathlib import Path
from sqlalchemy import create_engine, text

DDL = '''CREATE TABLE IF NOT EXISTS user_wallet_commands (
    id uuid PRIMARY KEY,
    payload_hash char(64) NOT NULL,
    result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
)'''


def install(engine):
    with engine.begin() as db:
        owner = db.scalar(text('SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname=current_schema()'))
        if not owner:
            raise ValueError('User schema owner required')
        db.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))'))
        db.exec_driver_sql(DDL)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url-file', type=Path, required=True)
    args = parser.parse_args()
    engine = create_engine(args.database_url_file.read_text().strip())
    try:
        install(engine)
    finally:
        engine.dispose()
