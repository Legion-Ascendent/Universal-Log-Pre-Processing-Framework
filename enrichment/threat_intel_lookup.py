"""
enrichment/threat_intel_lookup.py — Phase P14 (optional/stretch).

Simulates a "known-bad IP" match against a small, hardcoded, fully offline
list. This is a DEMO SIMULATION, not a real threat-intelligence feed -- the
addresses below are either IPs reused from this project's own sample data
(so the demo shows a guaranteed real hit), or RFC 5737 reserved
documentation/example addresses (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), which are permanently reserved for documentation and are
never assigned to real-world infrastructure. No live API calls, ever --
same offline-first philosophy as the rest of the project (requirement j).
"""

from typing import FrozenSet

# Deliberately includes 2 real IPs from this project's own sample data, so
# calling this against actual pipeline output produces a genuine hit during
# the demo, not just a hit against a value nobody will ever see again:
#   - 203.0.113.55 appears in BOTH unknown_format_samples.log and the mixed log file
#   - 10.10.10.5 appears in the mixed log file (the login_failed JSON/CEF lines) --
#     a nice demo narrative too: an IP that just failed a login is ALSO flagged.
_KNOWN_BAD_IPS: FrozenSet[str] = frozenset({
    "203.0.113.55",
    "10.10.10.5",
    "192.0.2.50",
    "192.0.2.77",
    "192.0.2.200",
    "198.51.100.23",
    "203.0.113.99",
})


def is_known_bad_ip(ip: str) -> bool:
    """Checks whether an IP appears on a small bundled hardcoded "known bad" list.

    Args:
        ip: an IPv4 address string, e.g. '203.0.113.55'.

    Returns:
        True if `ip` (after stripping whitespace) exactly matches an entry
        on the bundled list, False otherwise -- including for None, empty,
        or malformed input, which never raises here.
    """
    if not ip:
        return False
    return ip.strip() in _KNOWN_BAD_IPS