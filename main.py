#!/usr/bin/env python3
"""
CyberWatch: Real-Time Network Intrusion Detection System
==========================================================
Entry point. Run with elevated privileges (see README) since raw packet
capture requires it on every platform:

    sudo python3 main.py      # Linux / macOS
    (Run as Administrator)    # Windows

Flow: login_screen() -> main_app() (src/gui.py)
"""

from src.auth import login_screen
from src.gui import main_app

if __name__ == "__main__":
    login_screen(on_success=main_app)
