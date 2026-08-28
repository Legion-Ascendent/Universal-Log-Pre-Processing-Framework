"""
parsers/syslog_processor.py

Phase P4 — Syslog processor.

Parses AND normalizes Syslog-format perimeter device logs in one function,
per the processor interface contract in the rulebook (Section 2.4). Covers
three real Cisco ASA-style message shapes, which together represent the
"firewall allow/deny" and "VPN connect/disconnect" event types this phase
is scoped to:

  1. Deny        — %ASA-4-106023: Deny <proto> src outside:IP/PORT dst inside:IP/PORT ...
  2. Built/Allow  — %ASA-6-302013: Built <dir> <proto> connection ... outside:IP/PORT ... inside:IP/PORT
  3. VPN session  — %ASA-6-11303x: Group <G> User <U> IP <IP> AnyConnect session established / disconnected

Any Syslog-shaped line whose body doesn't match one of these three known
message types raises ParserError rather than guessing — that's intentional,
matching the "malformed lines raise ParserError, not crash" rule. The
pipeline (P8) catches this, records it, and moves on; the raw copy already
made it into raw_events regardless.
"""

import os
import sys

# Allow this file to be run directly as `python3 parsers/syslog_processor.py`
# from the repo root, as well as imported normally — same pattern used
# throughout the other phases.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from datetime import datetime, timezone
from typing import Optional

from shared.contracts import (
    NormalizedEvent,
    ParserError,
    generate_event_id,
    now_iso8601,
    FORMAT_SYSLOG,
    ACTION_ALLOW,
    ACTION_DENY,
    ACTION_UNKNOWN,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_UNKNOWN,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_ICMP,
    PROTOCOL_UNKNOWN,
    CONFIDENCE_HIGH,
)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Syslog header: "Oct 12 14:32:07 FW01 <rest of message>"
_HEADER_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<message>.+)$"
)

# Cisco ASA message-ID prefix: "%ASA-4-106023: <body>"
_ASA_PREFIX_PATTERN = re.compile(
    r"^%(?P<vendor_tag>[A-Z0-9]+)-(?P<severity_num>\d+)-(?P<msg_id>\d+):\s*(?P<body>.+)$"
)

_DENY_PATTERN = re.compile(
    r"Deny\s+(?P<protocol>\w+)\s+src\s+\S+:(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)\s+"
    r"dst\s+\S+:(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)",
    re.IGNORECASE,
)

_BUILT_PATTERN = re.compile(
    r"Built\s+\w+\s+(?P<protocol>\w+)\s+connection.*?"
    r"outside:(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+).*?"
    r"inside:(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)",
    re.IGNORECASE,
)

_VPN_PATTERN = re.compile(
    r"Group\s+<(?P<group>[^>]+)>\s+User\s+<(?P<user>[^>]+)>\s+"
    r"IP\s+<(?P<ip>\d+\.\d+\.\d+\.\d+)>\s+(?P<status>.+)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Small mapping helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(month_abbr: str, day: str, time_str: str) -> str:
    """Converts a Syslog RFC3164 timestamp (which has no year) into a full
    ISO8601 UTC string, assuming the current year — the same assumption
    real Syslog collectors make.

    Raises:
        ParserError: if the timestamp pieces don't form a valid date/time.
    """
    year = datetime.now(timezone.utc).year
    try:
        parsed = datetime.strptime(f"{year} {month_abbr} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError as exc:
        raise ParserError(f"Could not parse Syslog timestamp: {month_abbr} {day} {time_str}") from exc
    return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _map_protocol(protocol_str: Optional[str]) -> str:
    """Maps a free-text protocol token to one of the PROTOCOL_* constants."""
    if not protocol_str:
        return PROTOCOL_UNKNOWN
    normalized = protocol_str.strip().upper()
    if normalized == "TCP":
        return PROTOCOL_TCP
    if normalized == "UDP":
        return PROTOCOL_UDP
    if normalized == "ICMP":
        return PROTOCOL_ICMP
    return PROTOCOL_UNKNOWN


def _map_asa_severity(severity_num_str: Optional[str]) -> str:
    """Maps a Cisco ASA severity number (0-7, lower = more severe) to one
    of the SEVERITY_* constants."""
    if severity_num_str is None:
        return SEVERITY_UNKNOWN
    try:
        level = int(severity_num_str)
    except ValueError:
        return SEVERITY_UNKNOWN
    if level <= 2:
        return SEVERITY_CRITICAL
    if level == 3:
        return SEVERITY_HIGH
    if level == 4:
        return SEVERITY_MEDIUM
    if level in (5, 6):
        return SEVERITY_LOW
    return SEVERITY_UNKNOWN


def _infer_vendor(message_body: str) -> Optional[str]:
    """Infers the device vendor from message shape. '%ASA-' is a Cisco ASA
    specific logging convention, so its presence is a reliable signal."""
    if message_body.startswith("%ASA-"):
        return "Cisco"
    return None


# ---------------------------------------------------------------------------
# Public processor function
# ---------------------------------------------------------------------------

def process_syslog(raw_text: str, raw_event_id: str) -> NormalizedEvent:
    """Parses a raw Syslog log line and returns a fully-formed NormalizedEvent.

    Args:
        raw_text: the untouched original log line.
        raw_event_id: the event_id already assigned to this line in raw_events.

    Returns:
        A NormalizedEvent dict matching the contract in shared/contracts.py.

    Raises:
        ParserError: if the line isn't Syslog-shaped, or its message body
            doesn't match any of the known Deny / Built / VPN patterns.
    """
    stripped = raw_text.strip()

    header_match = _HEADER_PATTERN.match(stripped)
    if not header_match:
        raise ParserError(f"Line does not match the expected Syslog header shape: {raw_text!r}")

    timestamp = _parse_timestamp(
        header_match.group("month"), header_match.group("day"), header_match.group("time")
    )
    message = header_match.group("message")
    vendor = _infer_vendor(message)

    asa_match = _ASA_PREFIX_PATTERN.match(message)
    severity_num = asa_match.group("severity_num") if asa_match else None
    body = asa_match.group("body") if asa_match else message

    deny_match = _DENY_PATTERN.search(body)
    built_match = _BUILT_PATTERN.search(body)
    vpn_match = _VPN_PATTERN.search(body)

    if deny_match:
        fields = deny_match.groupdict()
        action = ACTION_DENY
        protocol = _map_protocol(fields.get("protocol"))
        src_ip = fields.get("src_ip")
        dst_ip = fields.get("dst_ip")
        src_port = int(fields["src_port"]) if fields.get("src_port") else None
        dst_port = int(fields["dst_port"]) if fields.get("dst_port") else None

    elif built_match:
        fields = built_match.groupdict()
        action = ACTION_ALLOW
        protocol = _map_protocol(fields.get("protocol"))
        src_ip = fields.get("src_ip")
        dst_ip = fields.get("dst_ip")
        src_port = int(fields["src_port"]) if fields.get("src_port") else None
        dst_port = int(fields["dst_port"]) if fields.get("dst_port") else None

    elif vpn_match:
        fields = vpn_match.groupdict()
        status = (fields.get("status") or "").lower()
        # A VPN session lifecycle event isn't itself a firewall-rule-style
        # allow/deny decision. "established" reasonably maps to allow (a
        # connection was permitted); "disconnected" is a normal teardown,
        # not a deny, so it maps to unknown rather than misrepresenting it.
        action = ACTION_ALLOW if "established" in status else ACTION_UNKNOWN
        protocol = PROTOCOL_UNKNOWN
        src_ip = fields.get("ip")
        dst_ip = None
        src_port = None
        dst_port = None

    else:
        raise ParserError(f"Syslog message body did not match any known pattern: {message!r}")

    return {
        "normalized_id": generate_event_id(),
        "raw_event_id": raw_event_id,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "action": action,
        "protocol": protocol,
        "device_vendor": vendor,
        "severity": _map_asa_severity(severity_num),
        "source_format": FORMAT_SYSLOG,
        "parser_confidence": CONFIDENCE_HIGH,
        "normalized_at": now_iso8601(),
    }


if __name__ == "__main__":
    # Manual isolation test — proves P4 works with zero dependency on any
    # other phase. Run directly with:
    #   python3 parsers/syslog_processor.py
    print("=" * 60)
    print("Part 1: processing every line in sample_logs/syslog_samples.log")
    print("=" * 60)

    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sample_logs",
        "syslog_samples.log",
    )

    all_sample_ok = True
    line_count = 0
    with open(sample_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line_count += 1
            fake_raw_id = generate_event_id()
            try:
                event = process_syslog(line, fake_raw_id)
                print(f"[OK]   {line[:70]}...")
                print(f"       -> action={event['action']} severity={event['severity']} "
                      f"src={event['src_ip']} dst={event['dst_ip']} proto={event['protocol']}")
            except ParserError as exc:
                all_sample_ok = False
                print(f"[FAIL] Unexpected ParserError on a real sample line: {exc}")

    print(f"\nProcessed {line_count} sample lines.\n")

    print("=" * 60)
    print("Part 2: deliberately malformed lines should raise ParserError, not crash")
    print("=" * 60)

    malformed_lines = [
        "This is not a syslog line at all",
        "Oct 12 14:32:07 FW01 %ASA-6-999999: Some completely unrecognized message type here",
    ]

    malformed_ok = True
    for line in malformed_lines:
        try:
            process_syslog(line, generate_event_id())
            malformed_ok = False
            print(f"[FAIL] Expected ParserError but none was raised for: {line!r}")
        except ParserError as exc:
            print(f"[OK]   Correctly raised ParserError: {exc}")

    print("\n" + "=" * 60)
    if all_sample_ok and malformed_ok:
        print("P4 DEFINITION OF DONE: PASSED")
    else:
        print("P4 DEFINITION OF DONE: FAILED — see FAIL lines above")