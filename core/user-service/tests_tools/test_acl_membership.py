from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID
import sys
import unittest

from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from user_service import acl_membership


class AclMembershipTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tenant = UUID("00000000-0000-4000-8000-000000000001")
        self.group = UUID("00000000-0000-4000-8000-000000000002")
        self.body = acl_membership.MembershipLookup(
            tenant_id=self.tenant, group_id=self.group, subject="verified-user",
        )

    def request(self, authorization, tenant):
        return SimpleNamespace(headers={"authorization": authorization}, state=SimpleNamespace(tenant_id=tenant))

    async def test_rejects_unconfigured_bad_credential_and_tenant_mismatch_before_storage(self):
        wrong = UUID("00000000-0000-4000-8000-000000000003")
        cases = [
            ({}, "Bearer owner-only", self.tenant, 503),
            ({"ACL_MEMBERSHIP_LOOKUP_TOKEN": "owner-only"}, "Bearer arbitrary", self.tenant, 401),
            ({"ACL_MEMBERSHIP_LOOKUP_TOKEN": "owner-only"}, "Bearer owner-only", wrong, 403),
        ]
        for env, credential, tenant, expected in cases:
            with self.subTest(status=expected), patch.dict("os.environ", env, clear=True), patch.object(
                acl_membership, "get_db_session", side_effect=AssertionError("Database was accessed")
            ), self.assertRaises(HTTPException) as error:
                await acl_membership.lookup_membership(self.body, self.request(credential, tenant))
            self.assertEqual(error.exception.status_code, expected)

    async def test_query_matches_group_tenant_and_active_native_subject(self):
        session = SimpleNamespace(scalar=AsyncMock(return_value=True))
        with patch.dict("os.environ", {"ACL_MEMBERSHIP_LOOKUP_TOKEN": "owner-only"}, clear=True), patch.object(
            acl_membership, "get_db_session", return_value=session
        ):
            response = await acl_membership.lookup_membership(self.body, self.request("Bearer owner-only", self.tenant))
        self.assertEqual(response, {"member": True})
        query = session.scalar.await_args.args[0]
        sql = str(query)
        for predicate in (
            "user_group_memberships.tenant_id", "users.tenant_id", "groups.tenant_id",
            "users.keycloak_sub", "users.is_active IS true", "users.deleted_at IS NULL", "groups.id",
        ):
            self.assertIn(predicate, sql)
        self.assertIn(self.tenant, query.compile().params.values())
        self.assertIn(self.group, query.compile().params.values())
        self.assertIn(self.body.subject, query.compile().params.values())
