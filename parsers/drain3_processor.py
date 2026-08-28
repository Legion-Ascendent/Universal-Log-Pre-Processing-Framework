"""
parsers/drain3_processor.py — Phase P11.

Automatically discovers structure in a log format nobody wrote a real parser
for (via Drain3 template mining), then heuristically maps whatever it finds
into the same NormalizedEvent shape every other processor produces.

This path is deliberately best-effort: it always reports CONFIDENCE_LOW, and
per the rulebook it must NEVER raise — even a line Drain3/the heuristics can't
make sense of still comes back as a valid, mostly-empty NormalizedEvent.
"""

import os
import re
from typing import List, Optional, Tuple

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

from shared.contracts import (
    ACTION_ALERT,
    ACTION_ALLOW,
    ACTION_DENY,
    ACTION_DROP,
    ACTION_UNKNOWN,
    CONFIDENCE_LOW,
    DRAIN3_STATE_PATH,
    FORMAT_UNKNOWN,
    NormalizedEvent,
    PROTOCOL_UNKNOWN,
    SEVERITY_UNKNOWN,
    generate_event_id,
    now_iso8601,
)

# ---------------------------------------------------------------------------
# Heuristic patterns (Section 4, Phase P11, step 3)
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IP_PORT_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$")
_PORT_PATTERN = re.compile(r"^\d{1,5}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?$")

# Small action vocabulary called for by the spec: block/deny/allow/alert
# (plus their common past-tense variants), mapped onto the shared ACTION_*
# constants — never a raw hardcoded string on the NormalizedEvent itself.
_ACTION_VOCABULARY = {
    "block": ACTION_DENY,
    "blocked": ACTION_DENY,
    "deny": ACTION_DENY,
    "denied": ACTION_DENY,
    "allow": ACTION_ALLOW,
    "allowed": ACTION_ALLOW,
    "alert": ACTION_ALERT,
    "alerted": ACTION_ALERT,
    "drop": ACTION_DROP,
    "dropped": ACTION_DROP,
}

_template_miner: Optional[TemplateMiner] = None


def _get_template_miner() -> TemplateMiner:
    """Lazily builds (and reuses) the module-level Drain3 TemplateMiner.

    Persists learned templates to DRAIN3_STATE_PATH (from shared/contracts.py)
    via drain3's FilePersistence, so the same unknown format is recognized
    across separate runs of the pipeline, not just within one process.

    Returns:
        A TemplateMiner instance backed by file persistence at DRAIN3_STATE_PATH.
    """
    global _template_miner
    if _template_miner is None:
        state_dir = os.path.dirname(DRAIN3_STATE_PATH)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        config = TemplateMinerConfig()
        # "|" and "=" help Drain3 tokenize pipe/kv-style unknown formats
        # (e.g. "SRC=1.2.3.4|ACT=BLOCKED") into separate wildcard tokens,
        # rather than treating a whole delimited chunk as one opaque token.
        # Deliberately NOT splitting on ":" here: an ISO8601 timestamp like
        # "2026-08-25T14:40:02" contains colons too, and splitting on them
        # would shred the timestamp into fragments. A combined "IP:PORT"
        # token (e.g. "192.168.5.6:9100") is instead recognized as a single
        # unit directly in _classify_tokens via _IP_PORT_PATTERN.
        config.drain_extra_delimiters = ["|", "="]

        persistence = FilePersistence(DRAIN3_STATE_PATH)
        _template_miner = TemplateMiner(persistence, config=config)

    return _template_miner


def _classify_tokens(
    values: List[str],
) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int], str, Optional[str]]:
    """Applies the Phase P11 field-guessing heuristics to extracted template tokens.

    Kept separate from the Drain3 calls so this pure logic (IP/port/action/
    timestamp guessing) can be exercised independently of the drain3 library
    and its on-disk state.

    Args:
        values: the ordered list of variable token strings Drain3 extracted
            from a raw log line, in the order they appeared in the line.

    Returns:
        A tuple of (src_ip, dst_ip, src_port, dst_port, action, timestamp).
        timestamp is None if no ISO8601-shaped token was found among values.
    """
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    action = ACTION_UNKNOWN
    timestamp: Optional[str] = None

    for i, value in enumerate(values):
        ip_port_match = _IP_PORT_PATTERN.match(value)
        if _TIMESTAMP_PATTERN.match(value):
            timestamp = value if value.endswith("Z") else value + "Z"
        elif ip_port_match:
            # A single combined "IP:PORT" token (e.g. "192.168.5.6:9100").
            ip_val, port_val = ip_port_match.group(1), int(ip_port_match.group(2))
            port_val = port_val if 0 <= port_val <= 65535 else None
            if src_ip is None:
                src_ip, src_port = ip_val, port_val
            elif dst_ip is None:
                dst_ip, dst_port = ip_val, port_val
        elif _IP_PATTERN.match(value):
            # A standalone IP token (port given separately, if at all).
            if src_ip is None:
                src_ip = value
            elif dst_ip is None:
                dst_ip = value
        elif _PORT_PATTERN.match(value):
            port_int = int(value)
            # "a token matching \d{1,5} in a position near an IP -> port":
            # treated as immediately following an already-classified IP token.
            if 0 <= port_int <= 65535 and i > 0 and _IP_PATTERN.match(values[i - 1]):
                preceding_ip = values[i - 1]
                if preceding_ip == src_ip and src_port is None:
                    src_port = port_int
                elif preceding_ip == dst_ip and dst_port is None:
                    dst_port = port_int
        else:
            lowered = value.strip().lower()
            if action == ACTION_UNKNOWN and lowered in _ACTION_VOCABULARY:
                action = _ACTION_VOCABULARY[lowered]

    return src_ip, dst_ip, src_port, dst_port, action, timestamp


def process_drain3(raw_text: str, raw_event_id: str) -> NormalizedEvent:
    """Parses a raw log line of an unrecognized format via Drain3 template mining
    and heuristically maps it into a NormalizedEvent.

    Feeds raw_text into a persistent drain3.TemplateMiner, pulls out the
    matched/new template's variable tokens, and guesses field meaning for
    IPs, ports, timestamps, and a small allow/deny/alert/drop vocabulary.
    Always reports CONFIDENCE_LOW, since this path is best-effort by design.

    Args:
        raw_text: the untouched original log line.
        raw_event_id: the event_id already assigned to this line in raw_events.

    Returns:
        A NormalizedEvent dict matching the contract in shared/contracts.py.
        Never raises: a line nothing useful can be extracted from still comes
        back as a valid NormalizedEvent with mostly None/ACTION_UNKNOWN fields.
    """
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    action = ACTION_UNKNOWN
    timestamp = now_iso8601()

    try:
        miner = _get_template_miner()
        result = miner.add_log_message(raw_text)
        template = result.get("template_mined") if result else None
        extracted = (
            miner.extract_parameters(template, raw_text, exact_matching=True)
            if template
            else None
        )
        values = [parameter.value for parameter in extracted] if extracted else []

        src_ip, dst_ip, src_port, dst_port, action, parsed_timestamp = _classify_tokens(values)
        if parsed_timestamp is not None:
            timestamp = parsed_timestamp
    except Exception:
        # Best-effort by design (Phase P11, step 5): an unrecognized/unusual
        # line must never crash the pipeline. Fall through with whatever was
        # salvaged so far — "we saw something and logged it" is still valid.
        pass

    return NormalizedEvent(
        normalized_id=generate_event_id(),
        raw_event_id=raw_event_id,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        action=action,
        protocol=PROTOCOL_UNKNOWN,
        device_vendor=None,
        severity=SEVERITY_UNKNOWN,
        source_format=FORMAT_UNKNOWN,
        parser_confidence=CONFIDENCE_LOW,
        normalized_at=now_iso8601(),
    )