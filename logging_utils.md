"""
src/logging_utils.py
=====================
Alert & Logging Module.

Named `logging_utils` (not `logging`) to avoid shadowing Python's stdlib
`logging` module. Persists intrusion events to a text log and can export
them to CSV for further analysis, matching Chapter 4.8 of the project
report.
"""

import csv
import os
from datetime import datetime

from config import LOG_FILE, CSV_FILE, LOG_DIR


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def log_intrusion(message: str, log_path: str = LOG_FILE) -> None:
    """Append a single alert line, prefixed with an ISO-8601 timestamp."""
    _ensure_log_dir()
    timestamp = datetime.now().isoformat(timespec="seconds")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"{timestamp}\t{message}\n")


def export_csv(log_path: str = LOG_FILE, csv_path: str = CSV_FILE) -> bool:
    """Convert the plain-text log into a CSV file with Timestamp/Event columns.

    Returns False (and does nothing) if there is no log file yet.
    """
    if not os.path.exists(log_path):
        return False

    _ensure_log_dir()
    with open(log_path, encoding="utf-8") as f:
        lines = [line.rstrip("\n") for line in f if line.strip()]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Event"])
        for line in lines:
            if "\t" in line:
                ts, event = line.split("\t", 1)
            else:
                ts, event = "", line
            writer.writerow([ts, event])

    return True
