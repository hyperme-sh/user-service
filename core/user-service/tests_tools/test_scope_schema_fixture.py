from pathlib import Path
import hashlib
from user_service.scope_schema import DDL_SHA256


def test_native_fixture_matches_additive_scope_schema():
    root=Path(__file__).resolve().parents[1]
    ddl=(root/'src/user_service/migrations/0002_scope_authority.sql').read_bytes()
    assert (root/'tests/fixtures/scope-authority.sql').read_bytes()==ddl
    assert hashlib.sha256(ddl).hexdigest()==DDL_SHA256
