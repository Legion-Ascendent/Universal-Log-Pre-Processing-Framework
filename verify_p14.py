"""
verify_p14.py — run this from your repo root to confirm Phase P14 works.

Usage:
    python verify_p14.py
"""

from enrichment.threat_intel_lookup import is_known_bad_ip

print("=== Listed IPs -> True ===")
assert is_known_bad_ip("203.0.113.55") is True
print("[OK] 203.0.113.55 -> True")
assert is_known_bad_ip("10.10.10.5") is True
print("[OK] 10.10.10.5 -> True")

print("\n=== Everything else -> False, no crashes ===")
assert is_known_bad_ip("192.168.5.6") is False
print("[OK] 192.168.5.6 (not listed) -> False")
assert is_known_bad_ip("8.8.8.8") is False
print("[OK] 8.8.8.8 (unrelated) -> False")
assert is_known_bad_ip("") is False
assert is_known_bad_ip(None) is False
print("[OK] empty/None -> False")

print("\nALL CHECKS PASSED")