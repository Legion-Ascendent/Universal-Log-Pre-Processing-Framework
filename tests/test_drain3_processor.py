"""
tests/test_drain3_processor.py

Regression tests for the Drain3 extraction bug (logpai/Drain3 issue #118):
extract_parameters() in drain3 v0.9.11 preprocesses extra_delimiters with
re.sub(delimiter, " ", log_message) -- treating each delimiter as a REGEX
PATTERN -- while mining's own tokenizer treats delimiters as LITERAL
strings. "|" is a regex metacharacter (alternation), so any pipe-delimited
line silently produced zero extracted values, even with a perfectly-mined
template.

parsers/drain3_processor.py no longer calls extract_parameters() at all;
these tests cover the manual replacement (_tokenize_for_extraction /
_extract_values_from_template) directly, plus one end-to-end check.
"""

import pytest

from parsers import drain3_processor
from shared.contracts import ACTION_ALLOW, CONFIDENCE_LOW, FORMAT_UNKNOWN, generate_event_id


@pytest.fixture
def isolated_drain3(tmp_path, monkeypatch):
    """Gives each test a fresh Drain3 state file and a fresh in-memory
    TemplateMiner, so learned templates from one test never leak into
    another (both tests and real usage share the same module-level
    singleton otherwise)."""
    state_path = str(tmp_path / "drain3_state.json")
    monkeypatch.setattr(drain3_processor, "DRAIN3_STATE_PATH", state_path)
    monkeypatch.setattr(drain3_processor, "_template_miner", None)
    yield


# ---------------------------------------------------------------------------
# Pure-function tests: the actual bug fix, isolated from mining/state entirely
# ---------------------------------------------------------------------------

def test_tokenize_for_extraction_treats_pipe_as_literal():
    """The exact character that broke drain3's own extract_parameters()
    ("|", a regex metacharacter) must be treated as a literal separator,
    not a regex pattern, and must not swallow the rest of the line."""
    tokens = drain3_processor._tokenize_for_extraction(
        "ALRT|2026-08-25T14:40:02|SEV3|SRC=192.168.5.6:9100|ACT=BLOCKED|RULE=RL-882",
        drain3_processor._EXTRA_DELIMITERS,
    )
    assert tokens == [
        "ALRT", "2026-08-25T14:40:02", "SEV3", "SRC",
        "192.168.5.6:9100", "ACT", "BLOCKED", "RULE", "RL-882",
    ]


def test_extract_values_from_template_pipe_delimited():
    """Uses the EXACT template and line from the real bug report -- with
    the fix, this must return the 5 wildcarded values instead of []."""
    template = "ALRT <*> <*> SRC <*> ACT <*> RULE <*>"
    raw_text = "ALRT|2026-08-25T14:40:02|SEV3|SRC=192.168.5.6:9100|ACT=BLOCKED|RULE=RL-882"

    values = drain3_processor._extract_values_from_template(template, raw_text)

    assert values == ["2026-08-25T14:40:02", "SEV3", "192.168.5.6:9100", "BLOCKED", "RL-882"]


def test_extract_values_from_template_whitespace_only_log():
    """Must stay compatible with plain whitespace-delimited unknown formats
    too, not just pipe-delimited ones -- no extra_delimiters needed here
    at all, so this exercises the plain-whitespace-split path."""
    template = "user <*> logged in"
    raw_text = "user johndoe logged in"

    values = drain3_processor._extract_values_from_template(template, raw_text)

    assert values == ["johndoe"]


def test_extract_values_from_template_no_template_returns_empty():
    assert drain3_processor._extract_values_from_template(None, "anything at all") == []


def test_extract_values_from_template_mismatched_shape_returns_empty():
    """If the raw line doesn't actually match the template's token count,
    fail safe (empty list) rather than guessing at a misaligned mapping."""
    template = "ALRT <*> <*> SRC <*> ACT <*> RULE <*>"
    raw_text = "totally different shape entirely"

    assert drain3_processor._extract_values_from_template(template, raw_text) == []


# ---------------------------------------------------------------------------
# End-to-end tests: process_drain3() itself, against a real (isolated) miner
# ---------------------------------------------------------------------------

def test_process_drain3_end_to_end_pipe_delimited(isolated_drain3):
    """Drain3 needs to see a token position vary at least twice before it
    learns that position is a wildcard (this is expected Drain3 behavior,
    not a bug) -- so this feeds 2 lines of the same shape and checks
    extraction on the second, which is where fields should now populate
    instead of coming back None/unknown."""
    # Note: the action word must actually DIFFER between the two lines --
    # Drain3 only learns a token position varies (and wildcards it) after
    # seeing two different values there. Keeping ACT identical on both
    # lines would leave "BLOCKED" as a fixed literal in the template
    # instead of a wildcard, and this test would then be checking the
    # test's own fixture data, not the extraction fix.
    line_1 = "ALRT|2026-08-25T14:40:02|SEV3|SRC=192.168.5.6:9100|ACT=BLOCKED|RULE=RL-882"
    line_2 = "ALRT|2026-08-25T14:41:19|SEV2|SRC=203.0.113.9:5100|ACT=ALLOWED|RULE=RL-119"

    drain3_processor.process_drain3(line_1, generate_event_id())
    result = drain3_processor.process_drain3(line_2, generate_event_id())

    assert result["src_ip"] == "203.0.113.9"
    assert result["src_port"] == 5100
    assert result["action"] == ACTION_ALLOW  # "ALLOWED" -> ACTION_ALLOW
    assert result["timestamp"] == "2026-08-25T14:41:19Z"
    assert result["parser_confidence"] == CONFIDENCE_LOW
    assert result["source_format"] == FORMAT_UNKNOWN


def test_process_drain3_end_to_end_whitespace_delimited(isolated_drain3):
    """Same end-to-end check, but for a plain whitespace-delimited unknown
    format with no pipes/equals at all -- confirms the fix didn't narrow
    support to only pipe-delimited formats."""
    line_1 = "connection from 10.0.0.5 was blocked"
    line_2 = "connection from 10.0.0.9 was allowed"

    drain3_processor.process_drain3(line_1, generate_event_id())
    result = drain3_processor.process_drain3(line_2, generate_event_id())

    assert result["src_ip"] == "10.0.0.9"
    assert result["parser_confidence"] == CONFIDENCE_LOW


def test_process_drain3_never_raises_on_garbage(isolated_drain3):
    """Unrelated to this bug, but a core P11 guarantee this fix must not
    have broken: total gibberish must still come back as a valid,
    non-crashing NormalizedEvent."""
    result = drain3_processor.process_drain3("!!! not a log line at all ???", generate_event_id())
    assert result["parser_confidence"] == CONFIDENCE_LOW
    assert result["source_format"] == FORMAT_UNKNOWN