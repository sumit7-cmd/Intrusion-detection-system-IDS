"""
src/gui.py
===========
CyberWatch Dashboard — the Tkinter application shell.

Wires together the modules that used to be one monolithic script:
    capture.py       -> live packets
    detection.py     -> rule evaluation
    logging_utils.py -> persistence / CSV export
    visualization.py -> packet-rate graph

Each module can be tested or reused independently of this file.
"""

import threading
import time

import tkinter as tk
from tkinter import scrolledtext, messagebox
import tkinter.ttk as ttk

from config import WINDOW_TITLE, WINDOW_SIZE, TIME_WINDOW, MAX_RATE_POINTS
from src.detection import IntrusionDetector
from src.capture import PacketCapture
from src.logging_utils import log_intrusion, export_csv
from src.visualization import PacketRateGraph


class CyberWatchApp:
    def __init__(self):
        self.detector = IntrusionDetector()
        self.capture = PacketCapture(on_packet=self._on_packet)

        self.packet_rate = []
        self._last_packet_count = 0

        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Arial", 11, "bold"), padding=6)

        self._build_ui()
        self._start_background_threads()

    # -- UI construction ------------------------------------------------------
    def _build_ui(self):
        tk.Label(
            self.root, text="CyberWatch IDS", font=("Arial", 24, "bold"),
            bg="#1e1e1e", fg="white",
        ).pack(pady=10)

        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack()

        self.packet_label = tk.Label(top, text="Packets: 0", fg="#00ff9f", bg="#1e1e1e")
        self.packet_label.grid(row=0, column=0, padx=20)

        self.alert_label = tk.Label(top, text="Alerts: 0", fg="#ff4d4d", bg="#1e1e1e")
        self.alert_label.grid(row=0, column=1, padx=20)

        self.status_label = tk.Label(top, text="Stopped", fg="#ffa500", bg="#1e1e1e")
        self.status_label.grid(row=0, column=2, padx=20)

        self.log_box = scrolledtext.ScrolledText(
            self.root, width=120, height=25, bg="#2d2d2d", fg="white",
        )
        self.log_box.pack(pady=10)
        self.log_box.tag_config("alert", foreground="red")

        frame = tk.Frame(self.root, bg="#1e1e1e")
        frame.pack(pady=20)

        ttk.Button(frame, text="Start", command=self.start).grid(row=0, column=0, padx=10)
        ttk.Button(frame, text="Stop", command=self.stop).grid(row=0, column=1, padx=10)
        ttk.Button(frame, text="Clear Logs", command=self.clear_logs).grid(row=0, column=2, padx=10)
        ttk.Button(frame, text="Graph", command=self.show_graph).grid(row=0, column=3, padx=10)
        ttk.Button(frame, text="Export CSV", command=self.export_csv).grid(row=0, column=4, padx=10)

    def _safe_update(self, func):
        self.root.after(0, func)

    # -- packet / alert plumbing ----------------------------------------------
    def _on_packet(self, features):
        def update():
            self.packet_label.config(text=f"Packets: {self.detector.total_packets}")
            self.log_box.insert(tk.END, f"{features.src} -> {features.dst} | {features.protocol}\n")
            self.log_box.see(tk.END)

        self._safe_update(update)

        for alert in self.detector.process_packet(features):
            self._trigger_alert(alert)

    def _trigger_alert(self, message):
        def update():
            self.log_box.insert(tk.END, message + "\n", "alert")
            self.alert_label.config(text=f"Alerts: {self.detector.total_alerts}")
            self.log_box.see(tk.END)

        self._safe_update(update)
        log_intrusion(message)

    # -- background threads ----------------------------------------------------
    def _start_background_threads(self):
        threading.Thread(target=self._calculate_rate_loop, daemon=True).start()
        threading.Thread(target=self._reset_counters_loop, daemon=True).start()

    def _calculate_rate_loop(self):
        while True:
            time.sleep(1)
            if self.capture.is_running:
                rate = self.detector.total_packets - self._last_packet_count
                self._last_packet_count = self.detector.total_packets
            else:
                rate = 0

            self.packet_rate.append(rate)
            if len(self.packet_rate) > MAX_RATE_POINTS:
                self.packet_rate.pop(0)

    def _reset_counters_loop(self):
        while True:
            time.sleep(TIME_WINDOW)
            self.detector.reset_counters()

    # -- button handlers ---------------------------------------------------------
    def start(self):
        self.capture.start()
        self.status_label.config(text="Running", foreground="green")

    def stop(self):
        self.capture.stop()
        self._last_packet_count = self.detector.total_packets
        self.status_label.config(text="Stopped", foreground="orange")

    def clear_logs(self):
        self.log_box.delete(1.0, tk.END)

    def show_graph(self):
        PacketRateGraph(self.root, self.packet_rate)

    def export_csv(self):
        if export_csv():
            messagebox.showinfo("Export", "CSV Exported!")
        else:
            messagebox.showwarning("Export", "No logs found yet — start monitoring first.")

    def run(self):
        self.root.mainloop()


def main_app():
    """Entry point used by src/auth.py after a successful login."""
    CyberWatchApp().run()
