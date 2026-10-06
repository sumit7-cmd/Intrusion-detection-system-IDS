"""Stateless and testable IDS detection engine."""

from collections import defaultdict
from dataclasses import dataclass


@dataclass
class PacketFeatures:
    src_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str = ""


@dataclass
class Alert:
    rule_id: str
    attack_type: str
    severity: str
    src_ip: str
    message: str


class DetectionEngine:
    def __init__(self, thresholds=None):
        self.thresholds = thresholds or {
            "high_traffic": 100,
            "port_scan": 10,
            "syn_flood": 50,
            "icmp_flood": 50,
            "dns_attack": 80,
            "bruteforce": 20,
        }
        self.window = defaultdict(lambda: {
            "packets": 0,
            "ports": set(),
            "syn": 0,
            "icmp": 0,
            "dns": 0,
            "connections": 0,
            "alerted": set(),
        })

    def process(self, packet: PacketFeatures) -> list[Alert]:
        state = self.window[packet.src_ip]
        state["packets"] += 1
        if packet.dst_port is not None:
            state["ports"].add(packet.dst_port)

        if packet.protocol.upper() == "TCP":
            if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
                state["syn"] += 1
            state["connections"] += 1

        if packet.protocol.upper() == "ICMP":
            state["icmp"] += 1

        if packet.protocol.upper() == "UDP" and packet.dst_port == 53:
            state["dns"] += 1

        return self._evaluate(packet.src_ip, state)

    def _evaluate(self, src_ip, state) -> list[Alert]:
        checks = [
            ("HIGH-TRAFFIC", "High Traffic", "high", state["packets"],
             self.thresholds["high_traffic"],
             "Packet volume exceeded the configured threshold."),
            ("PORT-SCAN", "Port Scanning", "high", len(state["ports"]),
             self.thresholds["port_scan"],
             "Distinct destination ports exceeded the configured threshold."),
            ("SYN-FLOOD", "SYN Flood", "critical", state["syn"],
             self.thresholds["syn_flood"],
             "TCP SYN volume exceeded the configured threshold."),
            ("ICMP-FLOOD", "ICMP Flood", "high", state["icmp"],
             self.thresholds["icmp_flood"],
             "ICMP packet volume exceeded the configured threshold."),
            ("DNS-ATTACK", "DNS Attack", "medium", state["dns"],
             self.thresholds["dns_attack"],
             "UDP/53 traffic exceeded the configured threshold."),
            ("BRUTE-FORCE", "Brute Force", "high", state["connections"],
             self.thresholds["bruteforce"],
             "Connection attempts exceeded the configured threshold."),
        ]

        alerts = []
        for rule_id, attack, severity, value, threshold, message in checks:
            if value > threshold and rule_id not in state["alerted"]:
                state["alerted"].add(rule_id)
                alerts.append(Alert(rule_id, attack, severity, src_ip, message))
        return alerts

    def reset(self) -> None:
        self.window.clear()
