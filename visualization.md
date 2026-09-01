"""
src/visualization.py
=====================
Data Visualization Module — live packet-rate graph.

The original prototype opened a Matplotlib figure and redrew it inside an
infinite `while True: plt.pause(1)` loop triggered directly from a button's
`command=`. Because Tkinter callbacks run on the GUI thread, that loop
never returned control to `root.mainloop()`, which froze the entire
dashboard the moment "Graph" was clicked.

This version embeds the figure in its own Toplevel window using
FigureCanvasTkAgg and redraws it with `root.after(...)`, so it cooperates
with the Tkinter event loop instead of blocking it.
"""

import tkinter as tk

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class PacketRateGraph:
    """A small Toplevel window that plots packets/sec over time."""

    def __init__(self, root: tk.Tk, packet_rate: list, refresh_ms: int = 1000):
        self.root = root
        self.packet_rate = packet_rate
        self.refresh_ms = refresh_ms

        self.window = tk.Toplevel(root)
        self.window.title("Packet Rate (Packets/sec)")
        self.window.geometry("600x400")

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.window)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self._closed = False
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        self._redraw()

    def _redraw(self):
        if self._closed:
            return

        self.ax.clear()
        self.ax.plot(self.packet_rate)
        self.ax.set_title("Packet Rate (Packets/sec)")
        self.ax.set_xlabel("seconds")
        self.ax.set_ylabel("packets/sec")
        self.canvas.draw()

        self.window.after(self.refresh_ms, self._redraw)

    def _on_close(self):
        self._closed = True
        plt.close(self.fig)
        self.window.destroy()
