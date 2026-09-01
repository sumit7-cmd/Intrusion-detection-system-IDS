"""
src/capture.py
===============
Packet Capture Module.

Wraps Scapy's sniff() and converts each captured packet into a
PacketFeatures object (header fields only — no payload inspection, so the
system never looks at application data, only who-talked-to-whom-how).
"""

import threading

from scapy.all import sniff, IP, TCP, UDP, ICMP

from config import IFACE, IGNORED_PREFIXES
from src.detection import PacketFeatures


class PacketCapture:
    """Runs Scapy sniffing on a background thread and reports packets."""

    def __init__(self, on_packet, iface: str = None):
        """
        Args:
            on_packet: callback invoked with a PacketFeatures instance for
                       every non-local IP packet captured.
            iface: network interface name; falls back to config.IFACE and
                   then to Scapy's own default interface if both are None.
        """
        self.on_packet = on_packet
        self.iface = iface or IFACE
        self._monitoring = threading.Event()
        self._thread = None

    @property
    def is_running(self) -> bool:
        return self._monitoring.is_set()

    def start(self):
        if self.is_running:
            return
        self._monitoring.set()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the sniff loop to stop.

        Scapy's sniff() blocks until its stop_filter returns True on a
        newly captured packet, so on a quiet interface the thread may
        linger until the next packet arrives — it is a daemon thread, so
        this never prevents the app from exiting.
        """
        self._monitoring.clear()

    def _sniff_loop(self):
        sniff(
            iface=self.iface,
            prn=self._handle_raw_packet,
            store=False,
            stop_filter=lambda _pkt: not self.is_running,
        )

    def _handle_raw_packet(self, packet):
        if not self.is_running:
            return
        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst

        if src.startswith(IGNORED_PREFIXES):
            return

        protocol = "IP"
        dport = None
        is_syn = False

        if packet.haslayer(TCP):
            protocol = "TCP"
            dport = packet[TCP].dport
            is_syn = bool(packet[TCP].flags & 0x02)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        features = PacketFeatures(
            src=src, dst=dst, protocol=protocol, dport=dport, is_syn=is_syn
        )
        self.on_packet(features)
