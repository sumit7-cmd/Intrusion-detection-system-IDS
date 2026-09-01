"""
tests/test_detection.py
=========================
Unit tests for the rule-based detection engine.

These tests import only `src.detection`, which has no Scapy or Tkinter
dependency, so they run anywhere Python 3 runs — no root privileges or
network interface required.

Run with:
    pytest tests/
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.detection import IntrusionDetector, PacketFeatures

TEST_THRESHOLDS = {
    "high_traffic": 5,
    "port_scan": 3,
    "syn_flood": 4,
    "icmp_flood": 4,
    "dns_attack": 4,
    "brute_force": 6,
}


def make_detector():
    return IntrusionDetector(thresholds=TEST_THRESHOLDS)


def test_no_alert_below_threshold():
    d = make_detector()
    for _ in range(3):
        alerts = d.process_packet(PacketFeatures(src="8.8.8.8", dst="1.2.3.4", protocol="TCP", dport=80))
    assert alerts == []
    assert d.total_alerts == 0


def test_high_traffic_alert_fires_once_threshold_crossed():
    d = make_detector()
    alerts = []
    for _ in range(TEST_THRESHOLDS["high_traffic"] + 1):
        alerts = d.process_packet(PacketFeatures(src="8.8.8.8", dst="1.2.3.4", protocol="TCP", dport=80))
    assert "[ALERT] High Traffic from 8.8.8.8" in alerts


def test_port_scan_detection_counts_distinct_ports():
    d = make_detector()
    alerts = []
    for port in range(1, TEST_THRESHOLDS["port_scan"] + 2):
        alerts = d.process_packet(
            PacketFeatures(src="9.9.9.9", dst="1.2.3.4", protocol="TCP", dport=port)
        )
    assert "[ALERT] Port Scan from 9.9.9.9" in alerts


def test_repeated_same_port_does_not_trigger_port_scan():
    d = make_detector()
    alerts = []
    for _ in range(20):
        alerts = d.process_packet(
            PacketFeatures(src="9.9.9.9", dst="1.2.3.4", protocol="TCP", dport=80)
        )
    assert "[ALERT] Port Scan from 9.9.9.9" not in alerts


def test_syn_flood_detection():
    d = make_detector()
    alerts = []
    for _ in range(TEST_THRESHOLDS["syn_flood"] + 1):
        alerts = d.process_packet(
            PacketFeatures(src="1.1.1.1", dst="2.2.2.2", protocol="TCP", dport=443, is_syn=True)
        )
    assert "[ALERT] SYN Flood from 1.1.1.1" in alerts


def test_icmp_flood_detection():
    d = make_detector()
    alerts = []
    for _ in range(TEST_THRESHOLDS["icmp_flood"] + 1):
        alerts = d.process_packet(PacketFeatures(src="3.3.3.3", dst="4.4.4.4", protocol="ICMP"))
    assert "[ALERT] ICMP Flood from 3.3.3.3" in alerts


def test_dns_attack_detection_requires_port_53():
    d = make_detector()
    alerts = []
    for _ in range(TEST_THRESHOLDS["dns_attack"] + 1):
        alerts = d.process_packet(
            PacketFeatures(src="5.5.5.5", dst="6.6.6.6", protocol="UDP", dport=53)
        )
    assert "[ALERT] DNS Attack from 5.5.5.5" in alerts


def test_non_dns_udp_does_not_trigger_dns_alert():
    d = make_detector()
    alerts = []
    for _ in range(20):
        alerts = d.process_packet(
            PacketFeatures(src="5.5.5.5", dst="6.6.6.6", protocol="UDP", dport=12345)
        )
    assert "[ALERT] DNS Attack from 5.5.5.5" not in alerts


def test_brute_force_detection_counts_all_connection_attempts():
    d = make_detector()
    alerts = []
    for _ in range(TEST_THRESHOLDS["brute_force"] + 1):
        alerts = d.process_packet(PacketFeatures(src="7.7.7.7", dst="8.8.4.4", protocol="TCP", dport=22))
    assert "[ALERT] Brute Force from 7.7.7.7" in alerts


def test_reset_counters_rearms_rules():
    d = make_detector()
    for _ in range(TEST_THRESHOLDS["high_traffic"] + 1):
        d.process_packet(PacketFeatures(src="8.8.8.8", dst="1.2.3.4", protocol="TCP", dport=80))

    d.reset_counters()
    alerts = d.process_packet(PacketFeatures(src="8.8.8.8", dst="1.2.3.4", protocol="TCP", dport=80))
    assert alerts == []


def test_total_packets_increments_for_every_packet():
    d = make_detector()
    for _ in range(10):
        d.process_packet(PacketFeatures(src="1.2.3.4", dst="5.6.7.8", protocol="TCP", dport=80))
    assert d.total_packets == 10
