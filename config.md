"""
config.py
=========
Central configuration for CyberWatch IDS.

Keeping every tunable value in one place makes the rule-based engine easy
to retune for a different network without touching detection logic, and
keeps credentials out of the code itself.
"""

import os

# ---------------------------------------------------------------------------
# Network interface
# ---------------------------------------------------------------------------
# Leave as None to let Scapy auto-select the default interface (conf.iface).
# Override with an environment variable if you need a specific NIC, e.g.:
#   Linux:   export CYBERWATCH_IFACE=eth0
#   macOS:   export CYBERWATCH_IFACE=en0
#   Windows: export CYBERWATCH_IFACE="Wi-Fi"
IFACE = os.environ.get("CYBERWATCH_IFACE") or None

# Private/loopback ranges that are ignored so the IDS focuses on
# north-south (external) traffic instead of local chatter.
IGNORED_PREFIXES = ("127.", "192.168.", "10.")

# ---------------------------------------------------------------------------
# Detection thresholds (per TIME_WINDOW seconds, per source IP)
# ---------------------------------------------------------------------------
TIME_WINDOW = 10              # seconds before per-IP counters reset

THRESHOLDS = {
    "high_traffic":    100,   # total packets            -> possible DoS
    "port_scan":        10,   # distinct destination ports -> port scan
    "syn_flood":        50,   # SYN packets               -> SYN flood
    "icmp_flood":       50,   # ICMP packets               -> ping flood
    "dns_attack":       80,   # DNS (UDP/53) packets       -> DNS attack
    "brute_force":      20,   # connection attempts        -> brute force
}

# ---------------------------------------------------------------------------
# Logging / export
# ---------------------------------------------------------------------------
LOG_DIR = os.environ.get("CYBERWATCH_LOG_DIR", "logs")
LOG_FILE = os.path.join(LOG_DIR, "logs.txt")
CSV_FILE = os.path.join(LOG_DIR, "logs.csv")

# ---------------------------------------------------------------------------
# Authentication (demo only — see README "Security Notes")
# ---------------------------------------------------------------------------
# The login screen is a UI placeholder for demonstration purposes. It is
# NOT a secure authentication system. Override the defaults with
# environment variables before running on any shared machine:
#   export CYBERWATCH_USER=myuser
#   export CYBERWATCH_PASS=my-strong-password
DEMO_USERNAME = os.environ.get("CYBERWATCH_USER", "admin")
DEMO_PASSWORD = os.environ.get("CYBERWATCH_PASS", "1234")

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
WINDOW_TITLE = "CyberWatch IDS"
WINDOW_SIZE = "1050x650"
MAX_RATE_POINTS = 50           # points kept for the packet-rate graph
