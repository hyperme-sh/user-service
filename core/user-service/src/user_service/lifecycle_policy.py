"""Account closure retention policy approved by the account/privacy owner.

Payment, order and tax records have seven calendar years of retention. At expiry,
only anonymous aggregate accounting totals may remain. An explicit preservation
hold has no automatic expiry; financial obligations must also be settled first.
These rules do not authorize deleting another person's/shared company records.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from controlplane_tenancy.account_profile import _preservation_hold_blocks

PROFILE_RETENTION = timedelta(days=89)
FINANCIAL_YEARS = 7


def aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("An aware timestamp is required")
    return value.astimezone(UTC)


def financial_deadline(
    record_finalized_at: datetime, last_financial_activity: datetime | None = None
) -> datetime:
    # Retain each record from its final financial activity, rather than resetting
    # every historical record to the account closure date. February 29 expires on February 28 in a non-leap year.
    anchor = aware_utc(record_finalized_at)
    if last_financial_activity is not None:
        anchor = max(anchor, aware_utc(last_financial_activity))
    try:
        return anchor.replace(year=anchor.year + FINANCIAL_YEARS)
    except ValueError:
        return anchor.replace(year=anchor.year + FINANCIAL_YEARS, day=28)


def financial_purge_due(
    *,
    now: datetime,
    retain_until: datetime,
    preservation_hold: bool,
    obligations_settled: bool,
) -> bool:
    current, deadline = aware_utc(now), aware_utc(retain_until)
    # Skipping the personal-data wait never waives financial retention,
    # preservation holds, or outstanding monetary obligations.
    return (
        not _preservation_hold_blocks(preservation_hold)
        and obligations_settled
        and current >= deadline
    )
