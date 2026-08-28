"""
verify_p11.py — run this from your repo root to confirm Phase P11 works.

Usage:
    pip install -r requirements.txt
    python3 verify_p11.py

This is a throwaway check, not part of the ULPF deliverable itself —
feel free to delete it once it passes.
"""

import os

from parsers.drain3_processor import process_drain3
from shared.contracts import generate_event_id, CONFIDENCE_LOW, FORMAT_UNKNOWN

# Clean slate so this script gives the same result every time you run it.
if os.path.exists("data/drain3_state.json"):
    os.remove("data/drain3_state.json")

test_lines = [
    "ALRT|2026-08-25T14:40:02|SEV3|SRC=192.168.5.6:9100|ACT=BLOCKED|RULE=RL-882",
    "ALRT|2026-08-25T14:41:19|SEV2|SRC=203.0.113.9:5100|ACT=ALLOWED|RULE=RL-119",
    "ALRT|2026-08-25T14:42:55|SEV1|SRC=198.51.100.4:6200|ACT=ALERT|RULE=RL-004",
    "totally unstructured gibberish !!! no ip no action here at all",
]

print("Feeding 4 never-seen-before log lines through process_drain3()...\n")

for line in test_lines:
    event = process_drain3(line, generate_event_id())
    assert event["parser_confidence"] == CONFIDENCE_LOW, "parser_confidence must always be CONFIDENCE_LOW"
    assert event["source_format"] == FORMAT_UNKNOWN, "source_format must always be FORMAT_UNKNOWN"
    print(f"  line:   {line}")
    print(f"  parsed: src_ip={event['src_ip']}  src_port={event['src_port']}  "
          f"action={event['action']}  timestamp={event['timestamp']}\n")

print("No crashes, every result had CONFIDENCE_LOW + FORMAT_UNKNOWN.")

state_path = "data/drain3_state.json"
assert os.path.exists(state_path), "Drain3 should have created a state file"
print(f"State file created at {state_path} -- Drain3 is persisting learned templates.\n")

print("ALL CHECKS PASSED")