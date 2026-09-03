"""
enrichment/geoip_lookup.py — Phase P13 (optional/stretch).

Tags an IP address with a country using a small, hand-made, fully offline
IP-range-to-country CSV (enrichment/ip_ranges.csv). No live API calls,
ever -- this must keep working in an air-gapped deployment (requirement j),
same philosophy as the rest of the project.
"""

import csv
import ipaddress
import os
from typing import List, Optional, Tuple

_IP_RANGES_CSV_PATH = os.path.join("enrichment", "ip_ranges.csv")

_ranges_cache: Optional[List[Tuple[ipaddress.IPv4Network, str]]] = None


def _load_ranges() -> List[Tuple[ipaddress.IPv4Network, str]]:
    """Loads and caches the bundled IP-range-to-country table.

    Cached at module level so repeated lookups (e.g. once per event during
    a pipeline run) don't re-read and re-parse the CSV from disk every time.

    Returns:
        A list of (network, country) tuples parsed from ip_ranges.csv, in
        file order.

    Raises:
        FileNotFoundError: if enrichment/ip_ranges.csv doesn't exist.
        ValueError: if a row's CIDR value can't be parsed as an IP network.
    """
    global _ranges_cache
    if _ranges_cache is None:
        ranges: List[Tuple[ipaddress.IPv4Network, str]] = []
        with open(_IP_RANGES_CSV_PATH, "r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                network = ipaddress.ip_network(row["cidr"].strip(), strict=False)
                ranges.append((network, row["country"].strip()))
        _ranges_cache = ranges
    return _ranges_cache


def lookup_country(ip: str) -> Optional[str]:
    """Looks up the country for an IP using a small bundled offline
    IP-range-to-country CSV.

    Args:
        ip: an IPv4 address string, e.g. '192.168.5.6'.

    Returns:
        The matching country name, or None if the IP isn't found in any
        bundled range, or if `ip` isn't a valid IP address string at all
        (e.g. None, empty, or malformed -- this never raises on bad input).
    """
    if not ip:
        return None

    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None

    for network, country in _load_ranges():
        if address in network:
            return country

    return None