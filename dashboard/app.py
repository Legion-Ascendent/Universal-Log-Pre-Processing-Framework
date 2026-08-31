"""
dashboard/app.py — Phase P15 (table & filter view) + Phase P16 (detail &
traceability view). Both phases live in this one file, per the rulebook.

Run with: streamlit run dashboard/app.py

This is a top-level script (per the golden rules, print()/st.* output is
fine here — unlike storage/, parsers/, detector/, enrichment/).
"""

import os
import sys

# streamlit only adds this file's own folder (dashboard/) to the import
# path, not the repo root above it -- so shared/ and storage/ (siblings of
# dashboard/, not children of it) aren't importable without this. Must run
# before the shared/storage imports below.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pandas as pd
import streamlit as st

from shared.contracts import (
    ACTION_ALERT,
    ACTION_ALLOW,
    ACTION_DENY,
    ACTION_DROP,
    ACTION_UNKNOWN,
    CONFIDENCE_LOW,
    FORMAT_UNKNOWN,
    KNOWN_FORMATS,
)
from storage.normalized_store import (
    filter_normalized_events,
    get_all_normalized_events,
    get_linked_raw_event,
)
from dashboard.timezone_utils import to_ist_display

st.set_page_config(page_title="ULPF Dashboard", layout="wide")
st.title("Universal Log Pre-Processing Framework")

# ---------------------------------------------------------------------------
# Phase P15: filters
# ---------------------------------------------------------------------------

# Dropdown options always come from the shared contract's known vocabulary
# (never a hardcoded string), so a filter is selectable even before any
# event of that kind has been ingested yet.
_FORMAT_OPTIONS = ["All"] + KNOWN_FORMATS + [FORMAT_UNKNOWN]
_ACTION_OPTIONS = ["All", ACTION_ALLOW, ACTION_DENY, ACTION_ALERT, ACTION_DROP, ACTION_UNKNOWN]

col1, col2, col3 = st.columns(3)
selected_format = col1.selectbox("Source format", options=_FORMAT_OPTIONS)
selected_action = col2.selectbox("Action", options=_ACTION_OPTIONS)
ip_filter = col3.text_input("IP address (exact match, src or dst)", value="")

filtered_events = filter_normalized_events(
    source_format=None if selected_format == "All" else selected_format,
    action=None if selected_action == "All" else selected_action,
    ip=ip_filter.strip() or None,
)

# Convert stored UTC timestamps to IST for display only, right before
# anything renders. Filtering above already happened in UTC against the
# database and is unaffected -- only what a person sees on screen changes.
for _event in filtered_events:
    _event["timestamp"] = to_ist_display(_event["timestamp"])
    _event["normalized_at"] = to_ist_display(_event["normalized_at"])

# Live count proving unified visibility across formats (requirement f) --
# computed over the *filtered* view, so it updates live as filters change.
distinct_formats_in_view = len({event["source_format"] for event in filtered_events})
st.markdown(f"### {len(filtered_events)} events across {distinct_formats_in_view} source formats")

# ---------------------------------------------------------------------------
# Phase P16: Drain3-vs-known-format counter (requirement e, live during demo)
# ---------------------------------------------------------------------------

drain3_count = sum(1 for e in filtered_events if e["parser_confidence"] == CONFIDENCE_LOW)
known_format_count = len(filtered_events) - drain3_count
st.markdown(
    f"**Parser path:** {known_format_count} via known-format parsers &nbsp;|&nbsp; "
    f"{drain3_count} via Drain3 (unknown-format) fallback"
)

# ---------------------------------------------------------------------------
# Table (now selectable, feeding Phase P16's detail panel) + empty states
# ---------------------------------------------------------------------------

if filtered_events:
    events_df = pd.DataFrame(filtered_events)
    selection = st.dataframe(
        events_df,
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row",
        key="events_table",
    )

    st.markdown("---")
    st.subheader("Event detail & traceability")

    selected_rows = selection.selection.rows if selection is not None else []
    if not selected_rows:
        st.caption("Select a row above to see its full normalized event and the original raw log line side by side.")
    else:
        selected_event = filtered_events[selected_rows[0]]
        raw_event = get_linked_raw_event(selected_event["normalized_id"])
        if raw_event is not None:
            raw_event = dict(raw_event)  # copy — avoid mutating whatever get_linked_raw_event returned
            raw_event["ingested_at"] = to_ist_display(raw_event["ingested_at"])

        detail_col, raw_col = st.columns(2)
        with detail_col:
            st.markdown("**Normalized event**")
            st.table(pd.DataFrame(list(selected_event.items()), columns=["Field", "Value"]).astype(str))

        with raw_col:
            st.markdown("**Linked raw event**")
            if raw_event is None:
                st.warning("No linked raw event found for this normalized event (data inconsistency).")
            else:
                st.code(raw_event["raw_text"], language=None)
                raw_meta = {k: v for k, v in raw_event.items() if k != "raw_text"}
                st.table(pd.DataFrame(list(raw_meta.items()), columns=["Field", "Value"]).astype(str))
else:
    all_events = get_all_normalized_events()
    if all_events:
        st.info("No events match the current filters.")
    else:
        st.info("No events ingested yet. Run the pipeline, then refresh this page.")