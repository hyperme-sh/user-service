"""Private TEST policy selection; request data never selects a retention mode."""

from __future__ import annotations

import os
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
