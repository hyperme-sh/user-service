"""The isolated native fixture is exactly the current standalone owner DDL."""
from pathlib import Path


def test_switch_schema_fixture_matches_standalone_migration():
    root = Path(__file__).resolve().parents[1]
    assert (root / 'tests/fixtures/owner-schema.sql').read_bytes() == (root / 'src/user_service/migrations/0001.sql').read_bytes()
