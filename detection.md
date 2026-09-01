"""
src/detection.py
=================
Rule-Based Detection Engine.

This module is intentionally free of any GUI or networking imports so it
can be unit tested in isolation (see tests/test_detection.py) and reused
outside of the Tkinter application if needed.

It tracks simple per-source-IP counters over a rolling time window and
raises an alert whenever a counter crosses its configured threshold,
mirroring the rules described in the project report:

    High Traffic   -> possible DoS
    Port Scan      -> reconnaissance
    SYN Flood      -> TCP resource exhaustion
    ICMP Flood     -> ping flood
    DNS Attack     -> amplification/reflection
    Brute Force    -> repeated connection attempts
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from config import THRESHOLDS


@dataclass
class PacketFeatures:
    """Minimal set of packet header fields the engine needs to reason about."""
    src: str
    dst: str
    protocol: str               # "TCP" | "UDP" | "ICMP" | "IP"
    dport: Optional[int] = None
    is_syn: bool = False


class IntrusionDetector:
    """Stateful rule-based detector keyed on source IP address."""

    def __init__(self, thresholds: dict = None):
        self.thresholds = thresholds or THRESHOLDS

        self.packet_count = defaultdict(int)
        self.port_scan = defaultdict(set)
        self.syn_count = defaultdict(int)
        self.icmp_count = defaultdict(int)
        self.dns_count = defaultdict(int)
        self.connection_attempts = defaultdict(int)

        self.total_packets = 0
        self.total_alerts = 0

    # -- ingestion ----------------------------------------------------------
    def process_packet(self, pkt: PacketFeatures) -> list:
        """Update counters for one packet and return any alerts it triggers."""
        self.total_packets += 1
        self.packet_count[pkt.src] += 1
        self.connection_attempts[pkt.src] += 1

        if pkt.protocol == "TCP":
            if pkt.dport is not None:
                self.port_scan[pkt.src].add(pkt.dport)
            if pkt.is_syn:
                self.syn_count[pkt.src] += 1

        elif pkt.protocol == "UDP":
            if pkt.dport == 53:
                self.dns_count[pkt.src] += 1

        elif pkt.protocol == "ICMP":
            self.icmp_count[pkt.src] += 1

        return self.check_rules(pkt.src)

    # -- rule evaluation ------------------------------------------------------
    def check_rules(self, ip: str) -> list:
        """Evaluate every rule for `ip` and return a list of alert strings.

        Each triggered rule message is only returned once per call; callers
        are responsible for periodically resetting counters (see
        `reset_counters`) which naturally re-arms each rule for the next
        time window instead of firing on every subsequent packet.
        """
        alerts = []

        if self.packet_count[ip] > self.thresholds["high_traffic"]:
            alerts.append(f"[ALERT] High Traffic from {ip}")

        if len(self.port_scan[ip]) > self.thresholds["port_scan"]:
            alerts.append(f"[ALERT] Port Scan from {ip}")

        if self.syn_count[ip] > self.thresholds["syn_flood"]:
            alerts.append(f"[ALERT] SYN Flood from {ip}")

        if self.icmp_count[ip] > self.thresholds["icmp_flood"]:
            alerts.append(f"[ALERT] ICMP Flood from {ip}")

        if self.dns_count[ip] > self.thresholds["dns_attack"]:
            alerts.append(f"[ALERT] DNS Attack from {ip}")

        if self.connection_attempts[ip] > self.thresholds["brute_force"]:
            alerts.append(f"[ALERT] Brute Force from {ip}")

        if alerts:
            self.total_alerts += len(alerts)

        return alerts

    # -- housekeeping ---------------------------------------------------------
    def reset_counters(self):
        """Clear all per-IP counters. Called every TIME_WINDOW seconds.

        Resetting (rather than only ever growing) is what re-arms a rule:
        without it, an IP that once crossed a threshold would trigger the
        same alert on literally every subsequent packet, which is why the
        original demo run produced ~150k duplicate 'High Traffic' alerts
        from a single noisy host (see data/sample_logs.csv).
        """
        self.packet_count.clear()
        self.port_scan.clear()
        self.syn_count.clear()
        self.icmp_count.clear()
        self.dns_count.clear()
        self.connection_attempts.clear()
