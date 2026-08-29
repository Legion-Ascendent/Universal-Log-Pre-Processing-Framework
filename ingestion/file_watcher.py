"""
ingestion/file_watcher.py

Phase P7 — Ingestion layer.

Reads sample log files line by line and hands each line to the pipeline as
(raw_text, source_name) pairs. This proves the exact same downstream code
path (format detection -> processing -> storage) that a live syslog
listener or a POSTed-log HTTP endpoint would use later, without needing to
build either of those yet — the pipeline doesn't care how a line arrived,
only that it did.

Deliberately tolerant of an incomplete sample_logs/ folder: this is
designed to be tested the moment even one *.log file exists, without
needing to wait for every other phase's sample data to land first.
"""

import os
import sys

# Allow this file to be run directly as `python3 ingestion/file_watcher.py`
# from the repo root, as well as imported normally — same pattern used
# throughout the other phases.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.contracts import SAMPLE_LOGS_DIR


def read_log_file(file_path: str, source_name: str) -> list:
    """Reads a log file and returns its non-empty raw log lines.

    Args:
        file_path: path to the .log file to read.
        source_name: a label identifying this source (e.g. the filename),
            used only to make the error message clearer if the read fails.

    Returns:
        A list of raw log line strings, in file order, stripped of
        surrounding whitespace/newlines, with blank lines removed.

    Raises:
        OSError: if the file can't be opened or read.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f]
    except OSError as exc:
        raise OSError(f"Could not read log file '{source_name}' at {file_path!r}: {exc}") from exc

    return [line for line in lines if line]


def watch_sample_logs_dir() -> list:
    """Reads every .log file in SAMPLE_LOGS_DIR and returns a combined list
    of (raw_text, source_name) tuples across all of them, ready to be fed
    one by one into the pipeline.

    Returns an empty list (rather than raising) if SAMPLE_LOGS_DIR doesn't
    exist yet or contains no .log files — a fresh clone before any sample
    data has been added is a valid, non-error state.

    Returns:
        A list of (raw_text, source_name) tuples, source_name being the
        filename (e.g. 'syslog_samples.log'), in filename-sorted order.
    """
    results: list = []

    if not os.path.isdir(SAMPLE_LOGS_DIR):
        return results

    log_filenames = sorted(
        filename for filename in os.listdir(SAMPLE_LOGS_DIR) if filename.endswith(".log")
    )

    for filename in log_filenames:
        file_path = os.path.join(SAMPLE_LOGS_DIR, filename)
        for line in read_log_file(file_path, filename):
            results.append((line, filename))

    return results


if __name__ == "__main__":
    # Manual isolation test — proves P7 works with zero dependency on any
    # other phase, and doesn't require ALL 4 sample files to exist yet
    # (P12's unknown_format_samples.log belongs to the teammate's track).
    # Run directly with:
    #   python3 ingestion/file_watcher.py
    print("=" * 60)
    print(f"Scanning '{SAMPLE_LOGS_DIR}/' for .log files...")
    print("=" * 60)

    combined = watch_sample_logs_dir()

    counts = {}
    for _raw_text, source_name in combined:
        counts[source_name] = counts.get(source_name, 0) + 1

    if not counts:
        print(
            "No .log files found yet. That's expected if none of P4/P5/P6/P12 have run in "
            "this environment — re-run this after at least one sample_logs/*.log file exists."
        )
    else:
        for source_name, count in sorted(counts.items()):
            print(f"  {source_name}: {count} lines")

    print(f"\nTotal lines across all found files: {len(combined)}")
    if combined:
        print(f"First line found: {combined[0]}")

    print("\n" + "=" * 60)
    print("Cross-checking read_log_file() directly against one file...")
    print("=" * 60)

    direct_test_ok = True
    if counts:
        first_source = sorted(counts.keys())[0]
        file_path = os.path.join(SAMPLE_LOGS_DIR, first_source)
        lines = read_log_file(file_path, first_source)
        print(f"read_log_file() on '{first_source}' returned {len(lines)} lines directly.")
        if len(lines) != counts[first_source]:
            direct_test_ok = False
            print(
                f"[FAIL] Mismatch: watch_sample_logs_dir() found {counts[first_source]} lines "
                f"but read_log_file() found {len(lines)}"
            )
        else:
            print("[OK]   Counts match between the two functions.")
    else:
        print("Skipped — no files available to test against yet.")

    print("\n" + "=" * 60)
    print("Confirming read_log_file() fails clearly on a missing file...")
    print("=" * 60)

    error_handling_ok = True
    try:
        read_log_file("sample_logs/this_file_does_not_exist.log", "this_file_does_not_exist.log")
        error_handling_ok = False
        print("[FAIL] Expected an OSError but none was raised.")
    except OSError as exc:
        print(f"[OK]   Correctly raised a clear error: {exc}")

    print("\n" + "=" * 60)
    if combined and direct_test_ok and error_handling_ok:
        print("P7 DEFINITION OF DONE: PASSED")
    elif not combined and direct_test_ok and error_handling_ok:
        print(
            "P7 DEFINITION OF DONE: PARTIAL — functions behave correctly, but no "
            "sample_logs/*.log files exist in this run yet (expected before P4/P5/P6)."
        )
    else:
        print("P7 DEFINITION OF DONE: FAILED — see FAIL lines above")