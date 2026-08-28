"""
parsers/json_processor.py

Phase P5 — JSON processor.

Parses AND normalizes JSON-format perimeter device logs in one function,
per the processor interface contract in the rulebook (Section 2.4).

Unlike Syslog, JSON logs are already structured — the hard part isn't
finding the fields, it's that different vendors use different KEY NAMES
for the same concept (e.g. 'src_ip' vs 'source_ip' vs 'srcip' vs 'src').
This processor handles that with a small key-alias table per field, plus
a value-alias table for the different words vendors use for the same
action/severity meaning, so it tolerates real-world vendor inconsistency
without needing a separate parser per vendor.

Sample data covers three distinct JSON "dialects" (ProxyGW, CloudGuard IDS,
EdgeWAF) that each name the same fields differently, on purpose — that's
what actually exercises the alias tables below.
"""

import os
import sys

# Allow this file to be run directly as `python3 parsers/json_processor.py`
# from the repo root, as well as imported normally — same pattern used
# throughout the other phases.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timezone
from typing import Any, Optional

from shared.contracts import (
    NormalizedEvent,
    ParserError,
    generate_event_id,
    now_iso8601,
    FORMAT_JSON,
    ACTION_ALLOW,
    ACTION_DENY,
    ACTION_ALERT,
    ACTION_DROP,
    ACTION_UNKNOWN,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
    SEVERITY_UNKNOWN,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_ICMP,
    PROTOCOL_UNKNOWN,
    CONFIDENCE_HIGH,
)


# ---------------------------------------------------------------------------
# Key-name alias tables — the different names vendors use for the same field
# ---------------------------------------------------------------------------

_TIMESTAMP_KEYS = ["ts", "timestamp", "time", "event_time", "@timestamp"]
_SRC_IP_KEYS = ["src_ip", "source_ip", "srcip", "src", "client_ip"]
_DST_IP_KEYS = ["dst_ip", "dest_ip", "destination_ip", "dstip", "dst", "server_ip"]
_SRC_PORT_KEYS = ["src_port", "source_port", "srcport", "sport"]
_DST_PORT_KEYS = ["dst_port", "dest_port", "destination_port", "dstport", "dport"]
_ACTION_KEYS = ["action", "verdict", "decision", "disposition"]
_PROTOCOL_KEYS = ["protocol", "proto"]
_VENDOR_KEYS = ["device", "vendor", "product", "device_vendor", "appliance"]
_SEVERITY_KEYS = ["severity", "sev", "priority", "level"]


# ---------------------------------------------------------------------------
# Value-alias tables — the different words vendors use for the same meaning
# ---------------------------------------------------------------------------

_ACTION_VALUE_ALIASES = {
    "allow": ACTION_ALLOW, "allowed": ACTION_ALLOW, "permit": ACTION_ALLOW, "permitted": ACTION_ALLOW,
    "deny": ACTION_DENY, "denied": ACTION_DENY, "block": ACTION_DENY, "blocked": ACTION_DENY,
    "alert": ACTION_ALERT, "alerted": ACTION_ALERT, "flagged": ACTION_ALERT,
    "drop": ACTION_DROP, "dropped": ACTION_DROP,
}

_SEVERITY_VALUE_ALIASES = {
    "low": SEVERITY_LOW, "info": SEVERITY_LOW, "informational": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM, "med": SEVERITY_MEDIUM, "moderate": SEVERITY_MEDIUM, "warning": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL, "crit": SEVERITY_CRITICAL, "severe": SEVERITY_CRITICAL,
}

_PROTOCOL_VALUE_ALIASES = {
    "tcp": PROTOCOL_TCP,
    "udp": PROTOCOL_UDP,
    "icmp": PROTOCOL_ICMP,
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _get_first(data_lower: dict, aliases: list) -> Optional[Any]:
    """Returns the value of the first alias key found in data_lower (a dict
    already keyed by lowercase field names), skipping explicit nulls.
    Returns None if none of the aliases are present."""
    for alias in aliases:
        if alias in data_lower and data_lower[alias] is not None:
            return data_lower[alias]
    return None


def _to_str(value: Any) -> Optional[str]:
    """Best-effort conversion to str. None stays None; anything else is
    stringified, so a source that sends a number where a string was
    expected doesn't break the whole event."""
    if value is None:
        return None
    return str(value)


def _to_int(value: Any) -> Optional[int]:
    """Best-effort conversion to int (handles the value already being an
    int, or being a numeric string). Returns None rather than raising if
    it can't be converted — one bad field shouldn't fail the whole event."""
    if value is None:
        return None
    if isinstance(value, bool):  # bool is a subclass of int in Python; exclude it
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _normalize_timestamp(value: Any) -> str:
    """Best-effort conversion of whatever timestamp value/format was found
    into the project's standard ISO8601 UTC string. Handles ISO8601 strings
    (with or without a trailing 'Z') and Unix epoch numbers (seconds or
    milliseconds). Falls back to the current processing time if the value
    is missing or unparseable — still lets the event through rather than
    failing it outright, since a missing timestamp shouldn't discard an
    otherwise-useful security event.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            seconds = value / 1000 if value > 10_000_000_000 else value
            return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError, OSError):
            pass

    if isinstance(value, str) and value.strip():
        candidate = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    return now_iso8601()


def _map_action(value: Any) -> str:
    if not isinstance(value, str):
        return ACTION_UNKNOWN
    return _ACTION_VALUE_ALIASES.get(value.strip().lower(), ACTION_UNKNOWN)


def _map_severity(value: Any) -> str:
    if not isinstance(value, str):
        return SEVERITY_UNKNOWN
    return _SEVERITY_VALUE_ALIASES.get(value.strip().lower(), SEVERITY_UNKNOWN)


def _map_protocol(value: Any) -> str:
    if not isinstance(value, str):
        return PROTOCOL_UNKNOWN
    return _PROTOCOL_VALUE_ALIASES.get(value.strip().lower(), PROTOCOL_UNKNOWN)


# ---------------------------------------------------------------------------
# Public processor function
# ---------------------------------------------------------------------------

def process_json(raw_text: str, raw_event_id: str) -> NormalizedEvent:
    """Parses a raw JSON log line and returns a fully-formed NormalizedEvent.

    Tolerates vendor-to-vendor key-naming differences via the alias tables
    above. Missing optional fields (e.g. no severity key present at all) do
    NOT cause a failure — they come through as None/unknown, since JSON is
    self-describing and partial data is still useful data.

    Args:
        raw_text: the untouched original log line (must be a single JSON object).
        raw_event_id: the event_id already assigned to this line in raw_events.

    Returns:
        A NormalizedEvent dict matching the contract in shared/contracts.py.

    Raises:
        ParserError: if raw_text isn't valid JSON, or isn't a JSON object
            (e.g. a bare JSON array or number, which can't represent one event).
    """
    stripped = raw_text.strip()
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ParserError(f"Line is not valid JSON: {raw_text!r}") from exc

    if not isinstance(data, dict):
        raise ParserError(
            f"JSON line must be an object representing one event, got {type(data).__name__}: {raw_text!r}"
        )

    data_lower = {str(k).lower(): v for k, v in data.items()}

    return {
        "normalized_id": generate_event_id(),
        "raw_event_id": raw_event_id,
        "timestamp": _normalize_timestamp(_get_first(data_lower, _TIMESTAMP_KEYS)),
        "src_ip": _to_str(_get_first(data_lower, _SRC_IP_KEYS)),
        "dst_ip": _to_str(_get_first(data_lower, _DST_IP_KEYS)),
        "src_port": _to_int(_get_first(data_lower, _SRC_PORT_KEYS)),
        "dst_port": _to_int(_get_first(data_lower, _DST_PORT_KEYS)),
        "action": _map_action(_get_first(data_lower, _ACTION_KEYS)),
        "protocol": _map_protocol(_get_first(data_lower, _PROTOCOL_KEYS)),
        "device_vendor": _to_str(_get_first(data_lower, _VENDOR_KEYS)),
        "severity": _map_severity(_get_first(data_lower, _SEVERITY_KEYS)),
        "source_format": FORMAT_JSON,
        "parser_confidence": CONFIDENCE_HIGH,
        "normalized_at": now_iso8601(),
    }


if __name__ == "__main__":
    # Manual isolation test — proves P5 works with zero dependency on any
    # other phase. Run directly with:
    #   python3 parsers/json_processor.py
    print("=" * 60)
    print("Part 1: processing every line in sample_logs/json_samples.log")
    print("=" * 60)

    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sample_logs",
        "json_samples.log",
    )

    all_sample_ok = True
    line_count = 0
    with open(sample_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line_count += 1
            try:
                event = process_json(line, generate_event_id())
                print(f"[OK]   {line[:70]}...")
                print(f"       -> vendor={event['device_vendor']!r} action={event['action']} "
                      f"severity={event['severity']} src={event['src_ip']} dst={event['dst_ip']} "
                      f"proto={event['protocol']}")
            except ParserError as exc:
                all_sample_ok = False
                print(f"[FAIL] Unexpected ParserError on a real sample line: {exc}")

    print(f"\nProcessed {line_count} sample lines across 3 different JSON dialects.\n")

    print("=" * 60)
    print("Part 2: deliberately malformed lines should raise ParserError, not crash")
    print("=" * 60)

    malformed_lines = [
        "{this is not actually valid json}",
        "[1, 2, 3]",
    ]
    malformed_ok = True
    for line in malformed_lines:
        try:
            process_json(line, generate_event_id())
            malformed_ok = False
            print(f"[FAIL] Expected ParserError but none was raised for: {line!r}")
        except ParserError as exc:
            print(f"[OK]   Correctly raised ParserError: {exc}")

    print("\n" + "=" * 60)
    print("Part 3: sparse/partial JSON should NOT raise — graceful degradation")
    print("=" * 60)

    graceful_ok = True
    try:
        event = process_json('{"action": "blocked"}', generate_event_id())
        print(f"[OK]   Minimal object still produced a valid event: {event}")
    except ParserError as exc:
        graceful_ok = False
        print(f"[FAIL] Should not have raised on a sparse-but-valid object: {exc}")

    try:
        epoch_event = process_json('{"ts": 1798000000, "src_ip": "1.2.3.4"}', generate_event_id())
        print(f"[OK]   Epoch timestamp handled: {epoch_event['timestamp']}")
    except ParserError as exc:
        graceful_ok = False
        print(f"[FAIL] Should not have raised on an epoch timestamp: {exc}")

    print("\n" + "=" * 60)
    if all_sample_ok and malformed_ok and graceful_ok:
        print("P5 DEFINITION OF DONE: PASSED")
    else:
        print("P5 DEFINITION OF DONE: FAILED — see FAIL lines above")