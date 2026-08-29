"""
pipeline.py

Phase P8 — Pipeline orchestrator.

The glue script: wires ingestion -> raw storage -> format detection ->
the correct processor -> normalized storage, for every log line.

Self-upgrading by design: if storage/normalized_store.py (P10) or
parsers/drain3_processor.py (P11) don't exist yet, this file falls back
to a stub with the exact same function signature, so the pipeline still
runs end-to-end right now. The moment either teammate file lands (e.g.
after a `git pull`), the real import succeeds automatically and the stub
is never used again -- no code change needed here.
"""

import os
import sys

# pipeline.py lives directly at the repo root (unlike storage/, parsers/,
# etc., which are one folder down), so only ONE dirname() call is needed
# to reach the repo root -- not two, like the subfolder files use.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.contracts import (
    NormalizedEvent,
    ParserError,
    generate_event_id,
    now_iso8601,
    FORMAT_SYSLOG,
    FORMAT_JSON,
    FORMAT_CEF,
    FORMAT_UNKNOWN,
    ACTION_UNKNOWN,
    SEVERITY_UNKNOWN,
    PROTOCOL_UNKNOWN,
    CONFIDENCE_LOW,
)
from storage.raw_store import save_raw_event
from detector.format_detector import detect_format
from parsers.syslog_processor import process_syslog
from parsers.json_processor import process_json
from parsers.cef_processor import process_cef
from ingestion.file_watcher import watch_sample_logs_dir


# ---------------------------------------------------------------------------
# Self-upgrading imports: real module if it exists, stub with an identical
# signature otherwise. Each try/except is independent, so having only one
# of P10/P11 done doesn't block the other from being picked up.
# ---------------------------------------------------------------------------

try:
    from storage.normalized_store import save_normalized_event
    _USING_REAL_NORMALIZED_STORE = True
except ImportError:
    _USING_REAL_NORMALIZED_STORE = False

    def save_normalized_event(event: NormalizedEvent) -> None:
        """STUB (Phase P10 — storage/normalized_store.py — not found yet).
        Swapped automatically for the real function once that file exists;
        no change needed here."""
        print(
            f"       [STUB save_normalized_event] normalized_id={event['normalized_id'][:8]}... "
            f"(source_format={event['source_format']}, action={event['action']})"
        )


try:
    from parsers.drain3_processor import process_drain3
    _USING_REAL_DRAIN3 = True
except ImportError:
    _USING_REAL_DRAIN3 = False

    def process_drain3(raw_text: str, raw_event_id: str) -> NormalizedEvent:
        """STUB (Phase P11 — parsers/drain3_processor.py — not found yet).
        Returns a fake-but-valid NormalizedEvent so the pipeline still runs
        end-to-end for unknown-format lines. Swapped automatically for the
        real Drain3-backed function once that file exists."""
        return {
            "normalized_id": generate_event_id(),
            "raw_event_id": raw_event_id,
            "timestamp": now_iso8601(),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "action": ACTION_UNKNOWN,
            "protocol": PROTOCOL_UNKNOWN,
            "device_vendor": None,
            "severity": SEVERITY_UNKNOWN,
            "source_format": FORMAT_UNKNOWN,
            "parser_confidence": CONFIDENCE_LOW,
            "normalized_at": now_iso8601(),
        }


# Maps each format label to the processor that handles it. Built after the
# imports/stubs above so it always points at whichever version is active.
_PROCESSORS = {
    FORMAT_SYSLOG: process_syslog,
    FORMAT_JSON: process_json,
    FORMAT_CEF: process_cef,
    FORMAT_UNKNOWN: process_drain3,
}

# Populated by process_one_line() during a run_pipeline() call, and read by
# _print_summary() afterward. Only meant to be used within a single
# run_pipeline() call -- process_one_line() itself still returns None,
# matching the rulebook's interface contract exactly.
_last_run_log: list = []


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def process_one_line(raw_text: str, source_name: str) -> None:
    """Runs the full single-event pipeline on one raw log line:

    1. Saves the raw event immediately -- this happens first and
       unconditionally, regardless of what happens afterward.
    2. Detects its format.
    3. Routes to the matching processor (known-format processor, or
       Drain3 for FORMAT_UNKNOWN).
    4. Catches ParserError if raised -- records it and moves on, never
       crashes the pipeline.
    5. Saves the resulting NormalizedEvent, if one was produced.

    Args:
        raw_text: the untouched original log line.
        source_name: the source file/device this line came from.
    """
    raw_event = save_raw_event(raw_text, source_name)
    detected_format = detect_format(raw_text)
    processor = _PROCESSORS.get(detected_format)

    if processor is None:
        # Defensive only -- detect_format() only ever returns formats that
        # are all registered in _PROCESSORS above, so this shouldn't happen.
        print(f"[SKIP] source={source_name} format={detected_format} -> no processor registered")
        _last_run_log.append({"detected_format": detected_format, "status": "no_processor"})
        return

    try:
        normalized_event = processor(raw_text, raw_event["event_id"])
    except ParserError as exc:
        print(f"[SKIP] source={source_name} format={detected_format} -> parse error: {exc}")
        _last_run_log.append({"detected_format": detected_format, "status": "parse_error"})
        return

    save_normalized_event(normalized_event)
    print(
        f"[OK]   source={source_name} format={detected_format} -> normalized "
        f"(action={normalized_event['action']}, raw_id={raw_event['event_id'][:8]}...)"
    )
    _last_run_log.append({"detected_format": detected_format, "status": "normalized"})


def run_pipeline() -> None:
    """Reads every sample log line via the ingestion layer and runs
    process_one_line() on each, then prints a summary of what happened."""
    _last_run_log.clear()
    lines = watch_sample_logs_dir()

    if not lines:
        print("No sample log lines found in sample_logs/ — nothing to process.")
        return

    for raw_text, source_name in lines:
        process_one_line(raw_text, source_name)

    _print_summary(len(lines))


def _print_summary(total_lines: int) -> None:
    """Prints a per-format, per-status count summary of the last run_pipeline() call."""
    by_format_status: dict = {}
    for entry in _last_run_log:
        key = (entry["detected_format"], entry["status"])
        by_format_status[key] = by_format_status.get(key, 0) + 1

    print("\n" + "=" * 60)
    print("PIPELINE RUN SUMMARY")
    print("=" * 60)
    print(f"Total lines processed: {total_lines}")
    print()
    for (fmt, status), count in sorted(by_format_status.items()):
        print(f"  format={fmt:10s} status={status:15s} count={count}")

    normalized_count = sum(1 for e in _last_run_log if e["status"] == "normalized")
    error_count = sum(1 for e in _last_run_log if e["status"] == "parse_error")
    print()
    print(f"Successfully normalized: {normalized_count}/{total_lines}")
    print(f"Parse errors (raw still saved, just not normalized): {error_count}/{total_lines}")


if __name__ == "__main__":
    # Manual isolation test. Run directly with:  python3 pipeline.py
    from storage.raw_store import get_raw_event  # only used for the verification check below

    print("=" * 60)
    print("Module status:")
    print(
        f"  normalized storage : {'REAL' if _USING_REAL_NORMALIZED_STORE else 'STUB'} "
        f"({'storage/normalized_store.py found' if _USING_REAL_NORMALIZED_STORE else 'Phase P10 not found yet'})"
    )
    print(
        f"  Drain3 processor    : {'REAL' if _USING_REAL_DRAIN3 else 'STUB'} "
        f"({'parsers/drain3_processor.py found' if _USING_REAL_DRAIN3 else 'Phase P11 not found yet'})"
    )
    print("=" * 60 + "\n")

    print("=" * 60)
    print("Part 1: process_one_line() on 3 hand-crafted lines, proving the")
    print("        raw-write-always-happens rule even for a line that fails to normalize")
    print("=" * 60)

    _last_run_log.clear()
    test_cases = [
        (
            'Oct 12 14:32:07 FW01 %ASA-4-106023: Deny tcp src outside:203.0.113.55/443 '
            'dst inside:10.1.1.20/8080 by access-group "OUTSIDE_IN"',
            "manual_test_syslog_valid",
        ),
        ('{"src_ip": "1.2.3.4", "action": "blocked"}', "manual_test_json_valid"),
        (
            "Oct 12 14:32:07 FW01 %ASA-6-999999: Some completely unrecognized ASA message type here",
            "manual_test_syslog_unrecognized_body",
        ),
    ]

    for raw_text, source_name in test_cases:
        process_one_line(raw_text, source_name)

    print(f"\n{len(_last_run_log)} lines processed above (2 normalized, 1 parse error expected).")

    malformed_raw_text = test_cases[2][0]
    print("\nConfirming the parse-error line's raw copy still exists in raw storage...")
    # process_one_line() returns None by contract, so it doesn't hand back
    # the raw_event_id it generated -- verify via a direct DB-level check instead.
    import sqlite3
    from shared.contracts import DB_PATH

    connection = sqlite3.connect(DB_PATH)
    row = connection.execute(
        "SELECT event_id FROM raw_events WHERE raw_text = ?", (malformed_raw_text,)
    ).fetchone()
    connection.close()

    part1_ok = row is not None
    if part1_ok:
        print(f"[OK]   Confirmed: the parse-error line IS still in raw_events (event_id={row[0][:8]}...)")
    else:
        print("[FAIL] The parse-error line's raw copy is missing from raw_events!")

    print("\n" + "=" * 60)
    print("Part 2: full run_pipeline() against everything in sample_logs/")
    print("=" * 60)

    run_pipeline()

    print("\n" + "=" * 60)
    if part1_ok and _last_run_log:
        print("P8 DEFINITION OF DONE: PASSED")
    elif not _last_run_log:
        print(
            "P8 DEFINITION OF DONE: PARTIAL — pipeline ran without crashing, but no sample "
            "log lines were found in sample_logs/ (expected before P4/P5/P6 sample data exists)."
        )
    else:
        print("P8 DEFINITION OF DONE: FAILED — see FAIL lines above")