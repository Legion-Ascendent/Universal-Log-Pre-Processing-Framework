"""
storage/raw_store.py

Phase P1 — Raw storage module.

The one piece everything else in the pipeline depends on: writes a raw log
event to the database BEFORE any parsing is attempted, and can fetch a raw
event back by its ID. This module owns the `raw_events` table.

This module is self-sufficient: it can be run and tested with zero
dependency on any other phase (it creates its own table on first use, so
Phase P2's db_init.py does not need to have run first).
"""

import os
import sys

# Allow this file to be run directly as `python3 storage/raw_store.py` from
# the repo root, as well as imported normally, by making sure the repo root
# (the parent of this file's folder) is on sys.path either way. Without this,
# `from shared.contracts import ...` below would only work when the module
# is run with `python3 -m storage.raw_store` instead.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3
from typing import Optional

from shared.contracts import RawEvent, DB_PATH, generate_event_id, now_iso8601


def _get_connection() -> sqlite3.Connection:
    """Opens a connection to the ULPF SQLite database, creating the database
    file, its parent folder, and the `raw_events` table if they don't exist yet.

    Returns:
        An open sqlite3.Connection with row access by column name enabled.
    """
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS raw_events (
            event_id            TEXT PRIMARY KEY,
            raw_text             TEXT NOT NULL,
            source_name          TEXT,
            source_format_hint   TEXT,
            ingested_at           TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def save_raw_event(
    raw_text: str,
    source_name: str,
    source_format_hint: Optional[str] = None,
) -> RawEvent:
    """Stores a raw log line exactly as received, before any parsing is attempted.

    Generates a new event_id and ingestion timestamp, writes the row to the
    raw_events table, and returns the stored event. This write must succeed
    independent of anything downstream — nothing later in the pipeline may
    ever block or reverse it.

    Args:
        raw_text: the untouched original log line.
        source_name: e.g. a filename ('syslog_samples.log') or device identifier.
        source_format_hint: optional guess at the format from the ingestion layer.

    Returns:
        The RawEvent that was just stored.
    """
    event: RawEvent = {
        "event_id": generate_event_id(),
        "raw_text": raw_text,
        "source_name": source_name,
        "source_format_hint": source_format_hint,
        "ingested_at": now_iso8601(),
    }

    connection = _get_connection()
    try:
        connection.execute(
            """
            INSERT INTO raw_events (event_id, raw_text, source_name, source_format_hint, ingested_at)
            VALUES (:event_id, :raw_text, :source_name, :source_format_hint, :ingested_at)
            """,
            event,
        )
        connection.commit()
    finally:
        connection.close()

    return event


def get_raw_event(event_id: str) -> Optional[RawEvent]:
    """Fetches a single raw event by its ID.

    Args:
        event_id: the UUID4 string identifying the raw event.

    Returns:
        The matching RawEvent, or None if no row has that event_id.
    """
    connection = _get_connection()
    try:
        row = connection.execute(
            "SELECT event_id, raw_text, source_name, source_format_hint, ingested_at "
            "FROM raw_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return {
        "event_id": row["event_id"],
        "raw_text": row["raw_text"],
        "source_name": row["source_name"],
        "source_format_hint": row["source_format_hint"],
        "ingested_at": row["ingested_at"],
    }


if __name__ == "__main__":
    # Manual isolation test — proves P1 works with zero dependency on any
    # other phase. Run directly with:  python3 storage/raw_store.py
    test_lines = [
        ("Oct 12 14:32:07 FW01 %ASA-4-106023: Deny tcp src outside:203.0.113.55", "test_syslog.log"),
        ('{"src_ip": "198.51.100.9", "action": "blocked"}', "test_json.log"),
        ("CEF:0|Acme|Firewall|1.0|100|Blocked Connection|5|src=1.2.3.4 dst=5.6.7.8", "test_cef.log"),
    ]

    print("Saving 3 test raw events...\n")
    saved_events = []
    for raw_text, source_name in test_lines:
        saved = save_raw_event(raw_text, source_name)
        saved_events.append(saved)
        print(f"Saved: {saved}\n")

    print("Reading them back by event_id to confirm round-trip...\n")
    all_matched = True
    for saved in saved_events:
        fetched = get_raw_event(saved["event_id"])
        matched = fetched == saved
        all_matched = all_matched and matched
        print(f"[{'OK' if matched else 'MISMATCH'}] fetched: {fetched}\n")

    print("Confirming a lookup on a made-up ID returns None...")
    missing = get_raw_event("00000000-0000-0000-0000-000000000000")
    print(f"Result: {missing!r} (expected: None)\n")

    print("=" * 60)
    if all_matched and missing is None:
        print("P1 DEFINITION OF DONE: PASSED")
    else:
        print("P1 DEFINITION OF DONE: FAILED — check output above")