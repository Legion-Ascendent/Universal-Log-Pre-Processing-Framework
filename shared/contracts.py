"""
shared/contracts.py — FROZEN CONTRACT FILE.
Both teammates copy this file verbatim. Do not edit individually.
Defines every shared constant, path, data shape, and helper function
used across the whole ULPF pipeline, so every module speaks the same
language without needing to see any other module's code.
"""

import uuid
from datetime import datetime, timezone
from typing import TypedDict, Optional

# ---------------------------------------------------------------------------
# Shared file paths — always import these, never hardcode a path string
# ---------------------------------------------------------------------------

DB_PATH = "data/ulpf.db"
DRAIN3_STATE_PATH = "data/drain3_state.json"
SAMPLE_LOGS_DIR = "sample_logs"


# ---------------------------------------------------------------------------
# ID / timestamp helpers — always use these, never roll your own
# ---------------------------------------------------------------------------

def generate_event_id() -> str:
    """Generates a new unique event ID.

    Returns:
        A UUID4 string, e.g. '550e8400-e29b-41d4-a716-446655440000'.
    """
    return str(uuid.uuid4())


def now_iso8601() -> str:
    """Gets the current time in the project's standard timestamp format.

    Returns:
        Current UTC time as an ISO 8601 string, e.g. '2026-08-25T14:32:07Z'.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Format labels — always use these constants, never hardcode the strings
# ---------------------------------------------------------------------------

FORMAT_SYSLOG = "syslog"
FORMAT_JSON = "json"
FORMAT_CEF = "cef"
FORMAT_UNKNOWN = "unknown"

KNOWN_FORMATS = [FORMAT_SYSLOG, FORMAT_JSON, FORMAT_CEF]


# ---------------------------------------------------------------------------
# Normalized vocabulary — every processor must map its data into ONLY
# these values for the 'action' / 'severity' / 'protocol' fields
# ---------------------------------------------------------------------------

ACTION_ALLOW = "allow"
ACTION_DENY = "deny"
ACTION_ALERT = "alert"
ACTION_DROP = "drop"
ACTION_UNKNOWN = "unknown"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
SEVERITY_UNKNOWN = "unknown"

PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"
PROTOCOL_ICMP = "ICMP"
PROTOCOL_UNKNOWN = "UNKNOWN"

CONFIDENCE_HIGH = "high"   # used by known-format (rule-based) processors
CONFIDENCE_LOW = "low"     # used by the Drain3 heuristic-mapped processor


# ---------------------------------------------------------------------------
# Data shape contracts — every module passes data around in EXACTLY this shape
# ---------------------------------------------------------------------------

class RawEvent(TypedDict):
    event_id: str                        # from generate_event_id()
    raw_text: str                        # the untouched original log line, unmodified
    source_name: str                     # e.g. 'syslog_samples.log' or a device identifier
    source_format_hint: Optional[str]    # optional guess from ingestion; may be None
    ingested_at: str                     # from now_iso8601()


class NormalizedEvent(TypedDict):
    normalized_id: str                   # from generate_event_id()
    raw_event_id: str                    # MUST match a RawEvent's event_id — the traceability link
    timestamp: str                       # event's own timestamp if parseable, else ingested_at; ISO8601
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    action: str                          # one of the ACTION_* constants above
    protocol: str                        # one of the PROTOCOL_* constants above
    device_vendor: Optional[str]
    severity: str                        # one of the SEVERITY_* constants above
    source_format: str                   # one of the FORMAT_* constants above
    parser_confidence: str               # CONFIDENCE_HIGH or CONFIDENCE_LOW
    normalized_at: str                   # from now_iso8601()


# ---------------------------------------------------------------------------
# Exceptions — every parser/processor must raise this, never a bare exception
# ---------------------------------------------------------------------------

class ParserError(Exception):
    """Raised when a processor cannot parse a raw log line.

    The pipeline must catch this, log/record it, and continue — it must
    NEVER prevent the raw event from already having been stored.
    """
    pass