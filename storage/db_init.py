"""
storage/db_init.py

Phase P2 — Database initializer.

One script that creates data/ulpf.db and applies the full schema
(storage/schema.sql — both raw_events and normalized_events, plus their
indexes) if they don't already exist. Safe to run any number of times.

Note on why this still matters even though P1's raw_store.py already
creates the raw_events table itself: raw_store.py only knows about the
table it owns. This script applies the FULL schema — including
normalized_events and all indexes — which is what P10's normalized
storage module (and later, pipeline.py and the dashboard) will need.
Both approaches are safe together because every statement in schema.sql
uses IF NOT EXISTS.
"""

import os
import sys

# Allow this file to be run directly as `python3 storage/db_init.py` from
# the repo root, as well as imported normally — same pattern as raw_store.py.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3

from shared.contracts import DB_PATH

# Resolved relative to this file's own location, not the current working
# directory, so this works no matter where the script is invoked from.
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


def init_db() -> None:
    """Creates the SQLite database at DB_PATH and applies schema.sql.

    Every statement in schema.sql uses CREATE TABLE/INDEX IF NOT EXISTS,
    so this is fully idempotent — safe to call once, twice, or on every
    app startup, with no risk of errors or existing-data loss on repeat runs.
    """
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with open(SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
        schema_sql = schema_file.read()

    connection = sqlite3.connect(DB_PATH)
    try:
        connection.executescript(schema_sql)
        connection.commit()
    finally:
        connection.close()


def _get_table_names() -> set:
    """Internal helper for the isolation test below: lists tables that
    currently exist in the database."""
    connection = sqlite3.connect(DB_PATH)
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        connection.close()
    return {row[0] for row in rows}


if __name__ == "__main__":
    # Manual isolation test — proves P2 works with zero dependency on any
    # other phase having run first. Run directly with:
    #   python3 storage/db_init.py
    print(f"Initializing database at: {DB_PATH}")
    init_db()

    tables = _get_table_names()
    print(f"Tables present: {sorted(tables)}")

    expected_tables = {"raw_events", "normalized_events"}
    first_run_ok = expected_tables.issubset(tables)

    print("\nRunning init_db() a second time to confirm it's idempotent...")
    init_db()
    tables_after_second_run = _get_table_names()
    second_run_ok = tables == tables_after_second_run

    print(f"Tables after second run: {sorted(tables_after_second_run)}")

    print("\n" + "=" * 60)
    if first_run_ok and second_run_ok:
        print("P2 DEFINITION OF DONE: PASSED")
    else:
        if not first_run_ok:
            print(f"P2 DEFINITION OF DONE: FAILED — missing tables: {expected_tables - tables}")
        if not second_run_ok:
            print("P2 DEFINITION OF DONE: FAILED — second run changed the table set")