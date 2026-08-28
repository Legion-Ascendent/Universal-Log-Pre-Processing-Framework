"""
parsers/cef_processor.py

Phase P6 — CEF processor.

Parses AND normalizes CEF-format (Common Event Format) perimeter device
logs in one function, per the processor interface contract in the
rulebook (Section 2.4).

CEF has two distinct parts:
  1. A pipe-delimited header:
       CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
  2. A space-delimited "key=value" extension section, where CEF defines
     standard abbreviated key names (src, dst, spt, dpt, act, proto, rt, ...)
     that most real CEF-emitting vendors use consistently. That
     standardization is the whole point of CEF as a format — unlike the
     JSON processor, this one leans on one alias table rather than needing
     several competing vendor dialects.

The one real parsing wrinkle: extension values can themselves contain
spaces (e.g. msg=Access blocked due to policy act=blocked), so a naive
str.split() on whitespace would cut a value in half. This processor finds
each "key=" boundary with a regex and slices between them instead, so
multi-word values survive intact and the key right after them still parses.

Known limitation (out of scope for this prototype): CEF allows a pipe or
equals sign inside a value to be escaped with a backslash. This processor
does not handle escaped delimiters — none of the sample data uses them,
and real-world CEF lines from perimeter devices rarely do either.
"""

import os
import sys

# Allow this file to be run directly as `python3 parsers/cef_processor.py`
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
    FORMAT_CEF,
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
# Extension key aliases — CEF's own standard abbreviations, plus the
# occasional long form some vendors also emit
# ---------------------------------------------------------------------------

_TIMESTAMP_KEYS = ["rt", "start", "end"]
_SRC_IP_KEYS = ["src", "sourceaddress"]
_DST_IP_KEYS = ["dst", "destinationaddress"]
_SRC_PORT_KEYS = ["spt", "sourceport"]
_DST_PORT_KEYS = ["dpt", "destinationport"]
_ACTION_KEYS = ["act", "deviceaction"]
_PROTOCOL_KEYS = ["proto", "transportprotocol"]

_ACTION_VALUE_ALIASES = {
    "allow": ACTION_ALLOW, "allowed": ACTION_ALLOW, "permit": ACTION_ALLOW,
    "permitted": ACTION_ALLOW, "accept": ACTION_ALLOW,
    "deny": ACTION_DENY, "denied": ACTION_DENY, "block": ACTION_DENY, "blocked": ACTION_DENY,
    "alert": ACTION_ALERT, "alerted": ACTION_ALERT, "flagged": ACTION_ALERT,
    "drop": ACTION_DROP, "dropped": ACTION_DROP,
}

_PROTOCOL_VALUE_ALIASES = {
    "tcp": PROTOCOL_TCP,
    "udp": PROTOCOL_UDP,
    "icmp": PROTOCOL_ICMP,
}


# ---------------------------------------------------------------------------
# CEF extension tokenizer
# ---------------------------------------------------------------------------

# Matches a CEF extension key immediately followed by '=', anchored to the
# start of the string or preceded by whitespace, so it only fires at true
# key boundaries and never on a stray '=' that happens to sit inside a value.
_EXTENSION_KEY_PATTERN = re.compile(r"(?:^|\s)([a-zA-Z][a-zA-Z0-9_.]*)=")


def _parse_extension(extension_str: str) -> dict:
    """Splits a CEF extension string into a dict of key -> value, correctly
    handling values that themselves contain spaces (a well-known CEF
    parsing gotcha) by slicing between consecutive 'key=' boundaries
    rather than naively splitting on whitespace."""
    matches = list(_EXTENSION_KEY_PATTERN.finditer(extension_str))
    result: dict = {}
    for i, match in enumerate(matches):
        key = match.group(1).lower()
        value_start = match.end()
        value_end = matches[i + 1].start() if i + 1 < len(matches) else len(extension_str)
        result[key] = extension_str[value_start:value_end].strip()
    return result


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _get_first(data: dict, aliases: list) -> Optional[str]:
    """Returns the value of the first alias key present (and non-empty) in
    the parsed extension dict, or None if none of the aliases matched."""
    for alias in aliases:
        value = data.get(alias)
        if value:
            return value
    return None


def _to_int(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value.strip())
    except (ValueError, TypeError):
        return None


def _normalize_timestamp(value: Optional[str]) -> str:
    """CEF's 'rt' (receipt time) is conventionally epoch milliseconds, but
    this also tolerates plain epoch-seconds or an ISO8601 string, and falls
    back to the current processing time if nothing usable is present —
    same philosophy as the other processors: a missing timestamp shouldn't
    discard an otherwise-useful security event."""
    if not value:
        return now_iso8601()
    stripped = value.strip()

    if stripped.isdigit():
        try:
            number = int(stripped)
            seconds = number / 1000 if number > 10_000_000_000 else number
            return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError, OSError):
            pass

    try:
        parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return now_iso8601()


def _map_action(value: Optional[str]) -> str:
    if not value:
        return ACTION_UNKNOWN
    return _ACTION_VALUE_ALIASES.get(value.strip().lower(), ACTION_UNKNOWN)


def _map_protocol(value: Optional[str]) -> str:
    if not value:
        return PROTOCOL_UNKNOWN
    return _PROTOCOL_VALUE_ALIASES.get(value.strip().lower(), PROTOCOL_UNKNOWN)


def _map_cef_severity(severity_str: str) -> str:
    """Maps CEF's header Severity field (standard 0-10 numeric scale, with
    an occasional word-based fallback some vendors use) to the SEVERITY_* constants."""
    stripped = severity_str.strip()
    try:
        level = int(stripped)
    except ValueError:
        word = stripped.lower()
        return {
            "low": SEVERITY_LOW,
            "medium": SEVERITY_MEDIUM, "med": SEVERITY_MEDIUM,
            "high": SEVERITY_HIGH,
            "very-high": SEVERITY_CRITICAL, "veryhigh": SEVERITY_CRITICAL, "critical": SEVERITY_CRITICAL,
        }.get(word, SEVERITY_UNKNOWN)

    if 0 <= level <= 3:
        return SEVERITY_LOW
    if 4 <= level <= 6:
        return SEVERITY_MEDIUM
    if 7 <= level <= 8:
        return SEVERITY_HIGH
    if 9 <= level <= 10:
        return SEVERITY_CRITICAL
    return SEVERITY_UNKNOWN


# ---------------------------------------------------------------------------
# Public processor function
# ---------------------------------------------------------------------------

def process_cef(raw_text: str, raw_event_id: str) -> NormalizedEvent:
    """Parses a raw CEF log line and returns a fully-formed NormalizedEvent.

    Args:
        raw_text: the untouched original log line.
        raw_event_id: the event_id already assigned to this line in raw_events.

    Returns:
        A NormalizedEvent dict matching the contract in shared/contracts.py.

    Raises:
        ParserError: if the line doesn't start with 'CEF:', or doesn't have
            all 8 required pipe-delimited header fields.
    """
    stripped = raw_text.strip()
    if not stripped.startswith("CEF:"):
        raise ParserError(f"Line does not start with the required 'CEF:' prefix: {raw_text!r}")

    without_prefix = stripped[len("CEF:"):]
    header_fields = without_prefix.split("|", 7)
    if len(header_fields) < 8:
        raise ParserError(
            f"CEF header does not have all 8 required pipe-delimited fields "
            f"(found {len(header_fields)}): {raw_text!r}"
        )

    (_cef_version, vendor, _product, _device_version,
     _signature_id, _name, severity_str, extension_str) = header_fields

    extension = _parse_extension(extension_str)

    return {
        "normalized_id": generate_event_id(),
        "raw_event_id": raw_event_id,
        "timestamp": _normalize_timestamp(_get_first(extension, _TIMESTAMP_KEYS)),
        "src_ip": _get_first(extension, _SRC_IP_KEYS),
        "dst_ip": _get_first(extension, _DST_IP_KEYS),
        "src_port": _to_int(_get_first(extension, _SRC_PORT_KEYS)),
        "dst_port": _to_int(_get_first(extension, _DST_PORT_KEYS)),
        "action": _map_action(_get_first(extension, _ACTION_KEYS)),
        "protocol": _map_protocol(_get_first(extension, _PROTOCOL_KEYS)),
        "device_vendor": vendor.strip() if vendor.strip() else None,
        "severity": _map_cef_severity(severity_str),
        "source_format": FORMAT_CEF,
        "parser_confidence": CONFIDENCE_HIGH,
        "normalized_at": now_iso8601(),
    }


if __name__ == "__main__":
    # Manual isolation test — proves P6 works with zero dependency on any
    # other phase. Run directly with:
    #   python3 parsers/cef_processor.py
    print("=" * 60)
    print("Part 1: processing every line in sample_logs/cef_samples.log")
    print("=" * 60)

    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sample_logs",
        "cef_samples.log",
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
                event = process_cef(line, generate_event_id())
                print(f"[OK]   {line[:70]}...")
                print(f"       -> vendor={event['device_vendor']!r} action={event['action']} "
                      f"severity={event['severity']} src={event['src_ip']} dst={event['dst_ip']} "
                      f"proto={event['protocol']}")
            except ParserError as exc:
                all_sample_ok = False
                print(f"[FAIL] Unexpected ParserError on a real sample line: {exc}")

    print(f"\nProcessed {line_count} sample lines across 3 vendors.\n")

    print("=" * 60)
    print("Part 2: deliberately malformed lines should raise ParserError, not crash")
    print("=" * 60)

    malformed_lines = [
        "This is not a CEF line at all",
        "CEF:0|OnlyVendor|MissingTheRestOfTheHeader",
    ]
    malformed_ok = True
    for line in malformed_lines:
        try:
            process_cef(line, generate_event_id())
            malformed_ok = False
            print(f"[FAIL] Expected ParserError but none was raised for: {line!r}")
        except ParserError as exc:
            print(f"[OK]   Correctly raised ParserError: {exc}")

    print("\n" + "=" * 60)
    print("Part 3: edge cases that should NOT raise")
    print("=" * 60)

    graceful_ok = True
    try:
        empty_ext_event = process_cef(
            "CEF:0|TestVendor|TestProduct|1.0|SIG-001|Test Event|5|", generate_event_id()
        )
        print(f"[OK]   Empty extension still produced a valid event: {empty_ext_event}")
    except ParserError as exc:
        graceful_ok = False
        print(f"[FAIL] Should not have raised on an empty extension: {exc}")

    try:
        spaced_value_line = (
            "CEF:0|TestVendor|TestProduct|1.0|SIG-002|Msg With Spaces Test|5|"
            "msg=Access blocked due to corporate policy act=blocked src=1.2.3.4"
        )
        spaced_event = process_cef(spaced_value_line, generate_event_id())
        assert spaced_event["action"] == ACTION_DENY, "act= right after a multi-word msg= should still parse"
        assert spaced_event["src_ip"] == "1.2.3.4", "src= after that should still parse too"
        print(
            f"[OK]   Multi-word extension value handled correctly — the key right after it "
            f"still parsed: action={spaced_event['action']} src={spaced_event['src_ip']}"
        )
    except (ParserError, AssertionError) as exc:
        graceful_ok = False
        print(f"[FAIL] Multi-word extension value handling broke: {exc}")

    print("\n" + "=" * 60)
    if all_sample_ok and malformed_ok and graceful_ok:
        print("P6 DEFINITION OF DONE: PASSED")
    else:
        print("P6 DEFINITION OF DONE: FAILED — see FAIL lines above")