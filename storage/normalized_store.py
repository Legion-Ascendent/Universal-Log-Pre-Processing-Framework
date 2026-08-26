"""
Phase P10

Writes and reads NormalizedEvent rows in the `normalized_events` table,
and resolves the traceability link back to the originating RawEvent in
`raw_events`. This is the module the dashboard (P15/P16) reads from.

Per the golden rules, this is a library module: it never calls print(),
it never hardcodes DB_PATH, and every function is fully type-hinted.
"""

import os
import sqlite3
from typing import Optional

from shared.contracts import DB_PATH, NormalizedEvent, RawEvent

_SCHEMA_PATH = os.path.join("storage", "schema.sql")


def _get_connection() -> sqlite3.Connection:
    """Opens a connection to the ULPF database, ensuring the schema exists.

    Creates the parent directory for DB_PATH if it doesn't exist yet, and
    applies storage/schema.sql (idempotent — uses CREATE TABLE IF NOT EXISTS)
    so this module is fully testable in isolation without depending on P2's
    db_init.py having run first.

    Returns:
        An open sqlite3.Connection with row_factory set to sqlite3.Row.

    Raises:
        sqlite3.Error: if the connection or schema application fails.
    """
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    with open(_SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
        connection.executescript(schema_file.read())

    return connection


def _row_to_normalized_event(row: sqlite3.Row) -> NormalizedEvent:
    """Converts a sqlite3.Row from normalized_events into a NormalizedEvent.

    Args:
        row: a row fetched from the normalized_events table.

    Returns:
        A NormalizedEvent dict matching the contract in shared/contracts.py.
    """
    return NormalizedEvent(
        normalized_id=row["normalized_id"],
        raw_event_id=row["raw_event_id"],
        timestamp=row["timestamp"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        action=row["action"],
        protocol=row["protocol"],
        device_vendor=row["device_vendor"],
        severity=row["severity"],
        source_format=row["source_format"],
        parser_confidence=row["parser_confidence"],
        normalized_at=row["normalized_at"],
    )


def _row_to_raw_event(row: sqlite3.Row) -> RawEvent:
    """Converts a sqlite3.Row from raw_events into a RawEvent.

    Args:
        row: a row fetched from the raw_events table.

    Returns:
        A RawEvent dict matching the contract in shared/contracts.py.
    """
    return RawEvent(
        event_id=row["event_id"],
        raw_text=row["raw_text"],
        source_name=row["source_name"],
        source_format_hint=row["source_format_hint"],
        ingested_at=row["ingested_at"],
    )


def save_normalized_event(event: NormalizedEvent) -> None:
    """Inserts a NormalizedEvent row into the normalized_events table.

    Args:
        event: the NormalizedEvent to persist.

    Returns:
        None.

    Raises:
        sqlite3.Error: if the insert fails (e.g. raw_event_id doesn't exist,
            or normalized_id already exists).
    """
    connection = _get_connection()
    try:
        connection.execute(
            """
            INSERT INTO normalized_events (
                normalized_id, raw_event_id, timestamp, src_ip, dst_ip,
                src_port, dst_port, action, protocol, device_vendor,
                severity, source_format, parser_confidence, normalized_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["normalized_id"],
                event["raw_event_id"],
                event["timestamp"],
                event["src_ip"],
                event["dst_ip"],
                event["src_port"],
                event["dst_port"],
                event["action"],
                event["protocol"],
                event["device_vendor"],
                event["severity"],
                event["source_format"],
                event["parser_confidence"],
                event["normalized_at"],
            ),
        )
        connection.commit()
    finally:
        connection.close()


def get_all_normalized_events() -> list[NormalizedEvent]:
    """Returns every normalized event, most recent first.

    Returns:
        A list of NormalizedEvent dicts ordered by normalized_at descending.

    Raises:
        sqlite3.Error: if the query fails.
    """
    connection = _get_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM normalized_events ORDER BY normalized_at DESC"
        ).fetchall()
        return [_row_to_normalized_event(row) for row in rows]
    finally:
        connection.close()


def filter_normalized_events(
    source_format: Optional[str] = None,
    action: Optional[str] = None,
    ip: Optional[str] = None,
) -> list[NormalizedEvent]:
    """Returns normalized events matching any given filters (all optional, combine with AND).

    Args:
        source_format: if given, only events with this exact source_format.
        action: if given, only events with this exact action.
        ip: if given, only events where this IP appears as either src_ip or dst_ip.

    Returns:
        A list of matching NormalizedEvent dicts, most recent first.

    Raises:
        sqlite3.Error: if the query fails.
    """
    clauses: list[str] = []
    params: list[str] = []

    if source_format is not None:
        clauses.append("source_format = ?")
        params.append(source_format)
    if action is not None:
        clauses.append("action = ?")
        params.append(action)
    if ip is not None:
        clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.append(ip)
        params.append(ip)

    query = "SELECT * FROM normalized_events"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY normalized_at DESC"

    connection = _get_connection()
    try:
        rows = connection.execute(query, params).fetchall()
        return [_row_to_normalized_event(row) for row in rows]
    finally:
        connection.close()


def get_linked_raw_event(normalized_id: str) -> Optional[RawEvent]:
    """Given a normalized_id, follows raw_event_id and returns the matching RawEvent.

    This is the function the dashboard's traceability view (P16) calls to
    show the original raw log line next to its normalized form.

    Args:
        normalized_id: the normalized_id to look up.

    Returns:
        The linked RawEvent dict, or None if normalized_id or its linked
        raw event doesn't exist.

    Raises:
        sqlite3.Error: if the query fails.
    """
    connection = _get_connection()
    try:
        normalized_row = connection.execute(
            "SELECT raw_event_id FROM normalized_events WHERE normalized_id = ?",
            (normalized_id,),
        ).fetchone()

        if normalized_row is None:
            return None

        raw_row = connection.execute(
            "SELECT * FROM raw_events WHERE event_id = ?",
            (normalized_row["raw_event_id"],),
        ).fetchone()

        if raw_row is None:
            return None

        return _row_to_raw_event(raw_row)
    finally:
        connection.close()
