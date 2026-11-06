"""Private TEST policy selection; request data never selects a retention mode."""

from __future__ import annotations

import os
import re
import copy
from sqlalchemy import text


def test_data_requested() -> bool:
    return (
        os.environ.get("FASTAPI_ENV", "").strip().lower() == "test"
        and os.environ.get("ACCOUNT_CLOSURE_RETENTION", "").strip().lower() == "none"
    )


async def database_test_data(connection) -> bool:
    enabled = await connection.scalar(text("SELECT public.account_test_data_enabled()"))
    if type(enabled) is not bool or enabled != test_data_requested():
        raise ValueError(
            "Private TEST retention configuration does not match the database"
        )
    return enabled


def completed_test_receipt(value):
    """Keep only verified aggregate counts after native identity compaction."""
    if (
        not isinstance(value, dict)
        or set(value)
        != {"complete", "roots_complete", "remaining", "deleted", "tables"}
        or value["complete"] is not True
        or value["roots_complete"] is not True
        or type(value["remaining"]) is not int
        or value["remaining"] != 0
        or type(value["deleted"]) is not int
        or value["deleted"] < 0
        or not isinstance(value["tables"], dict)
        or len(value["tables"]) > 100
        or any(
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name)
            or type(count) is not int
            or count < 0
            for name, count in value["tables"].items()
        )
        or sum(value["tables"].values()) != value["deleted"]
    ):
        raise ValueError("Complete aggregate TEST erasure receipt required")
    return copy.deepcopy(value)
