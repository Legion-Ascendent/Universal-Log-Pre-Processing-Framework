"""
detector/format_detector.py

Phase P3 — Format detector.

Given a raw log line, decides which known format it is (Syslog, JSON, CEF),
or marks it unknown so the pipeline can route it to the Drain3 auto-discovery
path (Phase P11) instead.

Detection order matters and is deliberate: JSON -> CEF -> Syslog -> unknown.
Each check is cheap and specific, so trying them in this order avoids one
format's check accidentally matching another format's line.
"""

import os
import sys

# Allow this file to be run directly as `python3 detector/format_detector.py`
# from the repo root, as well as imported normally — same pattern used in
# storage/raw_store.py and storage/db_init.py.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import re

from shared.contracts import FORMAT_SYSLOG, FORMAT_JSON, FORMAT_CEF, FORMAT_UNKNOWN


# RFC3164-style Syslog: "Oct 12 14:32:07 FW01 %ASA-4-106023: Deny tcp..."
_SYSLOG_RFC3164_PATTERN = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+"
)

# RFC5424-style Syslog: "<34>1 2026-08-25T14:32:07.003Z mymachine su - ID47 ..."
_SYSLOG_RFC5424_PATTERN = re.compile(
    r"^<\d{1,3}>\d+\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
)


def _is_json(raw_text: str) -> bool:
    """Checks whether a line is a JSON object.

    Requires the line to start with '{' before even attempting json.loads,
    so that a bare numeric or quoted-string line (which json.loads would
    technically also accept) never gets misclassified as a JSON log event.
    """
    stripped = raw_text.strip()
    if not stripped.startswith("{"):
        return False
    try:
        json.loads(stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _is_cef(raw_text: str) -> bool:
    """Checks whether a line is CEF (Common Event Format), which always
    starts with a literal 'CEF:' prefix."""
    return raw_text.strip().startswith("CEF:")


def _is_syslog(raw_text: str) -> bool:
    """Checks whether a line matches either common Syslog shape
    (RFC3164 or RFC5424 style timestamp + hostname)."""
    stripped = raw_text.strip()
    return bool(
        _SYSLOG_RFC3164_PATTERN.match(stripped)
        or _SYSLOG_RFC5424_PATTERN.match(stripped)
    )


def detect_format(raw_text: str) -> str:
    """Determines the format of a raw log line.

    Tries, in order: JSON -> CEF -> Syslog (RFC3164 or RFC5424 shape).
    If nothing matches, the line is treated as an unknown/proprietary
    format, meant to be routed to the Drain3 auto-discovery path.

    Args:
        raw_text: the untouched original log line.

    Returns:
        One of FORMAT_JSON, FORMAT_CEF, FORMAT_SYSLOG, or FORMAT_UNKNOWN
        (all from shared/contracts.py).
    """
    if not raw_text or not raw_text.strip():
        return FORMAT_UNKNOWN

    if _is_json(raw_text):
        return FORMAT_JSON
    if _is_cef(raw_text):
        return FORMAT_CEF
    if _is_syslog(raw_text):
        return FORMAT_SYSLOG
    return FORMAT_UNKNOWN


if __name__ == "__main__":
    # Manual isolation test — proves P3 works with zero dependency on any
    # other phase. These are hand-written examples, not P4/P5/P6/P12's real
    # sample files, exactly as the rulebook allows. Run directly with:
    #   python3 detector/format_detector.py
    test_cases = [
        (
            "Oct 12 14:32:07 FW01 %ASA-4-106023: Deny tcp src outside:203.0.113.55",
            FORMAT_SYSLOG,
            "Syslog (RFC3164 style)",
        ),
        (
            "<34>1 2026-08-25T14:32:07.003Z FW02 firewall - ID47 - Deny tcp src 203.0.113.55",
            FORMAT_SYSLOG,
            "Syslog (RFC5424 style)",
        ),
        (
            '{"src_ip": "198.51.100.9", "dst_ip": "10.1.1.20", "action": "blocked"}',
            FORMAT_JSON,
            "JSON",
        ),
        (
            "CEF:0|Acme|Firewall|1.0|100|Blocked Connection|5|src=1.2.3.4 dst=5.6.7.8 act=blocked",
            FORMAT_CEF,
            "CEF",
        ),
        (
            "ALRT|2026-08-25T14:40:02|SEV3|SRC=192.168.5.6:9100|ACT=BLOCKED|RULE=RL-882",
            FORMAT_UNKNOWN,
            "Fictional/novel format (should fall through to unknown)",
        ),
        (
            "{this is not actually valid json}",
            FORMAT_UNKNOWN,
            "Malformed JSON-looking line (should NOT be misclassified as JSON)",
        ),
    ]

    print("Running format detection tests...\n")
    all_passed = True
    for raw_text, expected, label in test_cases:
        actual = detect_format(raw_text)
        passed = actual == expected
        all_passed = all_passed and passed
        status = "OK" if passed else "FAIL"
        print(f"[{status}] {label}")
        print(f"       input:    {raw_text}")
        print(f"       expected: {expected}   actual: {actual}\n")

    print("=" * 60)
    if all_passed:
        print("P3 DEFINITION OF DONE: PASSED")
    else:
        print("P3 DEFINITION OF DONE: FAILED — see FAIL lines above")