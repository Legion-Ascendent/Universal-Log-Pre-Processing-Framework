"""
live_demo_watch.py

A genuinely LIVE, continuously-running version of ingestion, built
specifically for demo day.

file_watcher.py's watch_sample_logs_dir() (Phase P7) does a single,
one-time batch read -- it's what run_pipeline() uses, and it's correct
for that job. But it means demoing "watch a new format get ingested"
today requires stopping and re-running the whole pipeline, which looks
staged.

This script instead polls sample_logs/ in a loop and processes only
genuinely NEW lines the moment they appear -- so you can drop a brand-new
.log file in, or append a line to an existing one, WHILE this is running,
in front of an audience, and watch it get detected and normalized live,
with no restart.

It deliberately reuses pipeline.process_one_line() directly -- the exact
same tested code path as the batch run -- so there is no separate,
untested "demo-only" logic to trust. This script only adds the polling
loop around it.

Usage:
    python3 live_demo_watch.py

Then, in a separate terminal (or just your file explorer), add a new
.log file to sample_logs/, or append a line to an existing one, at any
point while this is running. Press Ctrl+C to stop.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.contracts import SAMPLE_LOGS_DIR
from ingestion.file_watcher import read_log_file
import pipeline

POLL_INTERVAL_SECONDS = 1.5


def watch_and_process_live():
    """Polls sample_logs/ forever, processing only lines that appear AFTER
    this function starts. Tracks progress per-file by line count.

    On startup, it takes a silent baseline of whatever's already in
    sample_logs/ (e.g. from an earlier `python3 pipeline.py` run) WITHOUT
    reprocessing or printing any of it -- reprocessing already-processed
    lines would create duplicate rows in the database, and printing them
    would bury the actual live demo moment under a wall of startup noise.
    Only content that shows up after this point counts as a live event.
    """
    processed_line_counts = {}  # filename -> how many lines already accounted for

    print("=" * 60)
    print("LIVE DEMO WATCH MODE")
    print("=" * 60)
    print(f"Watching '{SAMPLE_LOGS_DIR}/' for new or growing .log files...")

    if not os.path.isdir(SAMPLE_LOGS_DIR):
        os.makedirs(SAMPLE_LOGS_DIR, exist_ok=True)

    existing_filenames = sorted(f for f in os.listdir(SAMPLE_LOGS_DIR) if f.endswith(".log"))
    for filename in existing_filenames:
        file_path = os.path.join(SAMPLE_LOGS_DIR, filename)
        try:
            processed_line_counts[filename] = len(read_log_file(file_path, filename))
        except OSError:
            processed_line_counts[filename] = 0

    baseline_total = sum(processed_line_counts.values())
    print(f"Baseline: {len(existing_filenames)} existing file(s), {baseline_total} line(s) "
          f"already accounted for (not reprocessed).")
    print("Drop a new .log file in, or append a line to an existing one, any time.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            log_filenames = sorted(
                f for f in os.listdir(SAMPLE_LOGS_DIR) if f.endswith(".log")
            )

            for filename in log_filenames:
                file_path = os.path.join(SAMPLE_LOGS_DIR, filename)
                try:
                    current_lines = read_log_file(file_path, filename)
                except OSError:
                    continue  # file may be mid-write; just retry on the next poll

                already_processed = processed_line_counts.get(filename, 0)

                if len(current_lines) > already_processed:
                    is_new_file = filename not in processed_line_counts
                    if is_new_file:
                        print(f"\n>>> New file detected: {filename}")

                    for line in current_lines[already_processed:]:
                        preview = line if len(line) <= 100 else line[:100] + "..."
                        print(f"\n[NEW EVENT] from {filename}:")
                        print(f"  raw: {preview}")
                        pipeline.process_one_line(line, filename)

                    processed_line_counts[filename] = len(current_lines)

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n\nStopped. Everything processed so far is already saved in data/ulpf.db.")


if __name__ == "__main__":
    watch_and_process_live()