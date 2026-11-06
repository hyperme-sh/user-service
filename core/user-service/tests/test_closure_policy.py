from datetime import UTC, datetime, timedelta

import pytest
from user_service.lifecycle_policy import financial_deadline, financial_purge_due


def test_seven_calendar_years_and_late_lease_activity():
    closed = datetime(2024, 2, 29, 12, tzinfo=UTC)
    assert financial_deadline(closed) == datetime(2031, 2, 28, 12, tzinfo=UTC)
    later = datetime(2025, 1, 1, tzinfo=UTC)
    assert financial_deadline(closed, later) == datetime(2032, 1, 1, tzinfo=UTC)
    assert financial_deadline(closed, closed - timedelta(days=1)) == financial_deadline(
        closed
    )


def test_financial_cleanup_requires_expiry_settlement_and_hold_release():
    deadline = datetime(2033, 1, 1, tzinfo=UTC)
    for hold, settled, offset, expected in (
        (False, True, 0, True),
        (False, True, -1, False),
        (True, True, 100, False),
        (False, False, 100, False),
    ):
        assert (
            financial_purge_due(
                now=deadline + timedelta(seconds=offset),
                retain_until=deadline,
                preservation_hold=hold,
                obligations_settled=settled,
            )
            is expected
        )
    with pytest.raises(ValueError, match="aware"):
        financial_deadline(datetime(2026, 1, 1))


def test_test_plane_waives_personal_wait_only(monkeypatch):
    from controlplane_tenancy.account_profile import (
        ACCOUNT_PROFILE_RETENTION,
        _closure_retention,
        _preservation_hold_blocks,
    )

    monkeypatch.delenv("ACCOUNT_CLOSURE_RETENTION", raising=False)
    assert _closure_retention() == ACCOUNT_PROFILE_RETENTION == timedelta(days=89)
    for mode in ("schedule", "typo", "none", "NONE"):
        monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", mode)
        assert _closure_retention() == (
            timedelta(0) if mode.lower() == "none" else timedelta(days=89)
        )
        assert _preservation_hold_blocks(True) is True
        assert _preservation_hold_blocks(False) is False


@pytest.mark.parametrize("mode", [None, "schedule", "none", "NONE", "typo"])
def test_financial_wait_holds_and_obligations_are_independent_of_personal_mode(
    monkeypatch, mode
):
    if mode is None:
        monkeypatch.delenv("ACCOUNT_CLOSURE_RETENTION", raising=False)
    else:
        monkeypatch.setenv("ACCOUNT_CLOSURE_RETENTION", mode)
    deadline = datetime(2033, 1, 1, tzinfo=UTC)
    for now, hold, settled, expected in (
        (deadline - timedelta(seconds=1), False, True, False),
        (deadline, False, True, True),
        (deadline + timedelta(days=1), True, True, False),
        (deadline + timedelta(days=1), False, False, False),
    ):
        assert (
            financial_purge_due(
                now=now,
                retain_until=deadline,
                preservation_hold=hold,
                obligations_settled=settled,
            )
            is expected
        )
    with pytest.raises(ValueError, match="aware"):
        financial_purge_due(
            now=datetime(2026, 1, 1),
            retain_until=deadline,
            preservation_hold=True,
            obligations_settled=False,
        )


@pytest.mark.parametrize(
    "hold,settled", [(True, False), (True, True), (False, False), (False, True)]
)
def test_verified_test_policy_has_no_financial_wait_hold_or_settlement_fence(
    hold, settled
):
    assert (
        financial_purge_due(
            now=datetime(2026, 1, 1, tzinfo=UTC),
            retain_until=datetime(2033, 1, 1, tzinfo=UTC),
            preservation_hold=hold,
            obligations_settled=settled,
            test_data=True,
        )
        is True
    )


@pytest.mark.parametrize("invalid", [1, "true", None])
def test_financial_policy_requires_a_boolean_trusted_mode(invalid):
    with pytest.raises(ValueError, match="Explicit TEST"):
        financial_purge_due(
            now=datetime(2026, 1, 1, tzinfo=UTC),
            retain_until=datetime(2033, 1, 1, tzinfo=UTC),
            preservation_hold=True,
            obligations_settled=False,
            test_data=invalid,
        )
