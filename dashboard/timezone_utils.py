"""
dashboard/timezone_utils.py

DISPLAY-ONLY timezone conversion for the dashboard.

Every timestamp is stored throughout this project in UTC (see
shared/contracts.py's now_iso8601()) -- that's deliberate, and it's what
keeps events from different sources/formats comparable to each other,
which matters for a security tool correlating events across vendors.
Nothing about that storage convention changes here.

This module exists solely to convert an already-stored UTC timestamp
into an IST (India Standard Time) string for RENDERING to a person in
the dashboard. Storage, parsers, detector, and the pipeline are
untouched and continue to work in UTC exactly as before -- only import
from this module inside dashboard code, right before displaying a
timestamp to someone.
"""

from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

try:
    IST = ZoneInfo("Asia/Kolkata")
except Exception:
    IST = timezone(timedelta(hours=5, minutes=30))
_UTC = timezone.utc


def to_ist_display(utc_iso_string: str) -> str:
    """Converts a UTC ISO8601 timestamp (the project's standard stored
    format, e.g. '2026-08-25T14:32:07Z') into a human-readable IST string.

    Args:
        utc_iso_string: a UTC timestamp in the project's standard format.

    Returns:
        A human-readable IST string, e.g. '25 Aug 2026, 08:02:07 PM IST'.
        If the input can't be parsed, returns it unchanged rather than
        raising -- a display hiccup shouldn't be able to crash the
        dashboard over a formatting detail.
    """
    try:
        utc_dt = datetime.strptime(utc_iso_string, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_UTC)
        ist_dt = utc_dt.astimezone(IST)
        return ist_dt.strftime("%d %b %Y, %I:%M:%S %p IST")
    except (ValueError, TypeError):
        return utc_iso_string


if __name__ == "__main__":
    # Manual isolation test. Run directly with:
    #   python3 dashboard/timezone_utils.py
    test_cases = [
        ("2026-08-25T14:32:07Z", "same-day conversion (UTC afternoon -> IST evening)"),
        ("2026-08-25T20:15:00Z", "day-rollover case (UTC evening -> IST past midnight, next day)"),
        ("2026-01-01T00:00:00Z", "new year's UTC midnight -> IST already Jan 1st morning"),
        ("not a real timestamp", "malformed input should return unchanged, not crash"),
    ]

    print("Testing UTC -> IST display conversion...\n")
    for utc_string, label in test_cases:
        result = to_ist_display(utc_string)
        print(f"[{label}]")
        print(f"  UTC in:  {utc_string}")
        print(f"  IST out: {result}\n")

    print("=" * 60)
    print("Manually verify the times above look correct (IST = UTC + 5:30).")