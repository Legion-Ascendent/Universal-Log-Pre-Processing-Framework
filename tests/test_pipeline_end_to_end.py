"""
tests/test_pipeline_end_to_end.py

Phase P9 — Tests.

Two kinds of tests live here:

1. End-to-end tests that prove requirements (a) "no data loss" and (d)
   "traceability" TOGETHER, by running a real line through the real
   pipeline (pipeline.process_one_line) and then verifying, via direct
   SQL against the actual database file, that both a raw_events row and
   a normalized_events row exist and are correctly linked. Deliberately
   verified with raw SQL rather than through storage/normalized_store.py's
   own read functions, so the test checks ground truth rather than
   trusting the same module's read path to correctly reflect its own write.

2. Unit tests per known-format processor (P4/P5/P6), confirming a
   known-good line parses correctly and a deliberately malformed line
   raises ParserError -- fast, pure-function tests with no database
   involved at all.

Every database-touching test uses the `isolated_db` fixture below, which
redirects all reads/writes to a fresh temporary SQLite file for the
duration of that one test. This means running `pytest tests/` NEVER
writes into the real data/ulpf.db used for development/demo purposes --
your actual demo data is never at risk of being mixed with test rows.

Run with:  pytest tests/
"""

import os
import sys

# Allow this file to be run/discovered from anywhere by ensuring the repo
# root is on sys.path — same pattern used throughout the other phases.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3

import pytest

import pipeline
import storage.raw_store as raw_store_module
import storage.db_init as db_init_module

from shared.contracts import (
    ParserError,
    generate_event_id,
    FORMAT_SYSLOG,
    FORMAT_JSON,
    FORMAT_CEF,
    ACTION_DENY,
    ACTION_ALERT,
    SEVERITY_HIGH,
    PROTOCOL_TCP,
)
from parsers.syslog_processor import process_syslog
from parsers.json_processor import process_json
from parsers.cef_processor import process_cef


# ---------------------------------------------------------------------------
# Shared sample lines (hand-crafted and self-contained here, rather than
# read from sample_logs/*.log, so these tests don't silently break if
# someone edits the sample data files later)
# ---------------------------------------------------------------------------

SYSLOG_SAMPLE_LINE = (
    'Oct 12 14:32:07 FW01 %ASA-4-106023: Deny tcp src outside:203.0.113.55/443 '
    'dst inside:10.1.1.20/8080 by access-group "OUTSIDE_IN"'
)
JSON_SAMPLE_LINE = (
    '{"src_ip": "198.51.100.9", "dst_ip": "10.1.1.20", "action": "blocked", "severity": "high"}'
)
CEF_SAMPLE_LINE = (
    'CEF:0|Acme|Firewall|1.0|100|Blocked Connection|8|'
    'src=1.2.3.4 dst=5.6.7.8 spt=1025 dpt=443 act=blocked'
)

SYSLOG_UNRECOGNIZED_BODY_LINE = (
    "Oct 12 14:32:07 FW01 %ASA-6-999999: Some completely unrecognized message type here"
)


# ---------------------------------------------------------------------------
# Fixture: isolated temporary database
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_db(monkeypatch, tmp_path):
    """Redirects all database reads/writes to a fresh temporary SQLite file
    for the duration of one test, so the test suite never touches or
    pollutes the real data/ulpf.db used for development/demo purposes.

    Patches DB_PATH on every module that holds its own imported reference
    to it (each `from shared.contracts import DB_PATH` creates a separate
    binding), and applies the full schema up front via db_init.init_db()
    so both tables exist regardless of whether storage/normalized_store.py
    additionally creates its own table defensively.

    Returns:
        The path to the fresh temporary database file.
    """
    test_db_path = str(tmp_path / "test_ulpf.db")

    monkeypatch.setattr(raw_store_module, "DB_PATH", test_db_path)
    monkeypatch.setattr(db_init_module, "DB_PATH", test_db_path)
    db_init_module.init_db()

    try:
        import storage.normalized_store as normalized_store_module
        monkeypatch.setattr(normalized_store_module, "DB_PATH", test_db_path)
    except ImportError:
        pass  # Phase P10 not present yet — pipeline.py's own stub will be used instead

    return test_db_path


# ---------------------------------------------------------------------------
# Direct SQL verification helpers (independent of any storage module's own
# read functions, on purpose — see module docstring)
# ---------------------------------------------------------------------------

def _query_raw_event_by_text(db_path: str, raw_text: str):
    connection = sqlite3.connect(db_path)
    try:
        return connection.execute(
            "SELECT event_id, raw_text, source_name FROM raw_events WHERE raw_text = ?",
            (raw_text,),
        ).fetchone()
    finally:
        connection.close()


def _query_normalized_event_by_raw_id(db_path: str, raw_event_id: str):
    connection = sqlite3.connect(db_path)
    try:
        return connection.execute(
            "SELECT normalized_id, raw_event_id, source_format FROM normalized_events WHERE raw_event_id = ?",
            (raw_event_id,),
        ).fetchone()
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# End-to-end tests — requirements (a) no data loss + (d) traceability
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw_text,source_name,expected_format",
    [
        (SYSLOG_SAMPLE_LINE, "test_syslog", FORMAT_SYSLOG),
        (JSON_SAMPLE_LINE, "test_json", FORMAT_JSON),
        (CEF_SAMPLE_LINE, "test_cef", FORMAT_CEF),
    ],
)
def test_end_to_end_no_data_loss_and_traceability(isolated_db, raw_text, source_name, expected_format):
    """Proves requirements (a) and (d) together: running one line of each
    known format through the real pipeline results in BOTH a raw_events
    row AND a normalized_events row, with the normalized row's
    raw_event_id correctly pointing back to the raw row's event_id."""
    pipeline.process_one_line(raw_text, source_name)

    raw_row = _query_raw_event_by_text(isolated_db, raw_text)
    assert raw_row is not None, f"Raw event was not saved for source={source_name}"
    raw_event_id = raw_row[0]

    normalized_row = _query_normalized_event_by_raw_id(isolated_db, raw_event_id)
    assert normalized_row is not None, (
        f"No normalized event links back to raw_event_id={raw_event_id}. "
        f"If Phase P10 (storage/normalized_store.py) isn't implemented yet, this is expected."
    )
    assert normalized_row[1] == raw_event_id, "Traceability link is broken"
    assert normalized_row[2] == expected_format


def test_end_to_end_parse_failure_still_preserves_raw_event(isolated_db):
    """A line that fails to normalize must still have its raw copy saved —
    the lossless guarantee (requirement a) has to hold in the FAILURE case
    too, not just the success case. Also confirms no normalized row gets
    created for a line that genuinely couldn't be parsed."""
    pipeline.process_one_line(SYSLOG_UNRECOGNIZED_BODY_LINE, "test_malformed")

    raw_row = _query_raw_event_by_text(isolated_db, SYSLOG_UNRECOGNIZED_BODY_LINE)
    assert raw_row is not None, "Raw event must be preserved even when normalization fails"

    raw_event_id = raw_row[0]
    normalized_row = _query_normalized_event_by_raw_id(isolated_db, raw_event_id)
    assert normalized_row is None, "A failed parse should NOT have produced a normalized row"


# ---------------------------------------------------------------------------
# Unit tests — Syslog processor (Phase P4)
# ---------------------------------------------------------------------------

def test_syslog_known_good_line_parses_correctly():
    event = process_syslog(SYSLOG_SAMPLE_LINE, generate_event_id())
    assert event["action"] == ACTION_DENY
    assert event["src_ip"] == "203.0.113.55"
    assert event["dst_ip"] == "10.1.1.20"
    assert event["src_port"] == 443
    assert event["dst_port"] == 8080
    assert event["protocol"] == PROTOCOL_TCP
    assert event["device_vendor"] == "Cisco"
    assert event["source_format"] == FORMAT_SYSLOG


def test_syslog_malformed_line_raises_parser_error():
    with pytest.raises(ParserError):
        process_syslog("this is not a syslog line at all", generate_event_id())


def test_syslog_unrecognized_body_raises_parser_error():
    with pytest.raises(ParserError):
        process_syslog(SYSLOG_UNRECOGNIZED_BODY_LINE, generate_event_id())


# ---------------------------------------------------------------------------
# Unit tests — JSON processor (Phase P5)
# ---------------------------------------------------------------------------

def test_json_known_good_line_parses_correctly():
    event = process_json(JSON_SAMPLE_LINE, generate_event_id())
    assert event["action"] == ACTION_DENY
    assert event["src_ip"] == "198.51.100.9"
    assert event["dst_ip"] == "10.1.1.20"
    assert event["severity"] == SEVERITY_HIGH
    assert event["source_format"] == FORMAT_JSON


def test_json_different_dialect_key_aliases_still_map_correctly():
    """Confirms the alias-mapping actually earns its keep: a completely
    different vendor key-naming scheme (source_ip/destination_ip/verdict)
    lands in the exact same normalized fields as the 'standard' dialect above."""
    different_dialect_line = (
        '{"timestamp": "2026-08-25T14:44:12Z", "vendor": "CloudGuard IDS", '
        '"source_ip": "203.0.113.45", "destination_ip": "10.1.2.30", "verdict": "alert"}'
    )
    event = process_json(different_dialect_line, generate_event_id())
    assert event["src_ip"] == "203.0.113.45"
    assert event["dst_ip"] == "10.1.2.30"
    assert event["device_vendor"] == "CloudGuard IDS"
    assert event["action"] == ACTION_ALERT


def test_json_malformed_line_raises_parser_error():
    with pytest.raises(ParserError):
        process_json("{this is not valid json at all", generate_event_id())


# ---------------------------------------------------------------------------
# Unit tests — CEF processor (Phase P6)
# ---------------------------------------------------------------------------

def test_cef_known_good_line_parses_correctly():
    event = process_cef(CEF_SAMPLE_LINE, generate_event_id())
    assert event["action"] == ACTION_DENY
    assert event["src_ip"] == "1.2.3.4"
    assert event["dst_ip"] == "5.6.7.8"
    assert event["src_port"] == 1025
    assert event["dst_port"] == 443
    assert event["device_vendor"] == "Acme"
    assert event["severity"] == SEVERITY_HIGH
    assert event["source_format"] == FORMAT_CEF


def test_cef_malformed_line_raises_parser_error():
    with pytest.raises(ParserError):
        process_cef("this does not start with the required CEF prefix", generate_event_id())


def test_cef_incomplete_header_raises_parser_error():
    with pytest.raises(ParserError):
        process_cef("CEF:0|OnlyVendor|MissingTheRestOfTheHeader", generate_event_id())