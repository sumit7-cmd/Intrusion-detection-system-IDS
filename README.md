CyberWatch: Real-Time Network Intrusion Detection System
A lightweight, rule-based Network Intrusion Detection System (NIDS) built with Python, Scapy, and Tkinter. CyberWatch sniffs live network traffic, extracts header-only packet features, evaluates them against six threshold-based detection rules, and surfaces real-time alerts through a desktop dashboard — with logging and CSV export for later analysis.

original single-file prototype into a modular, tested codebase — see What changed from the original prototype.

Table of contents
Features
Architecture
Detection rules
Repository structure
Installation
Usage
Configuration
Testing
Security notes
Known issues we found in our own logs
What changed from the original prototype
Roadmap
Team
License
References
Features
Real-time packet capture on a live interface using Scapy — header fields only (source/destination IP, protocol, ports, TCP flags); no payload inspection, so it's privacy-safe by design.
Rule-based detection engine for six common attack patterns: high traffic (DoS), port scanning, SYN flood, ICMP flood, DNS attack, and brute force.
Live Tkinter dashboard: packet counter, alert counter, running/stopped status, color-coded (red) alert log, Start/Stop/Clear/Graph/Export controls.
Packet-rate graph (packets/sec) embedded in its own window, so you can visually spot traffic spikes.
Persistent logging to logs/logs.txt, exportable to logs/logs.csv for spreadsheet analysis or reporting.
Fully configurable thresholds, time window, network interface, and credentials via config.py / environment variables — no code edits required to retune for a different network.
Unit-tested detection logic (tests/test_detection.py) that runs without root privileges, a network interface, or even Scapy/Tkinter installed, since the rule engine has zero GUI/networking dependencies.
Architecture
See docs/ARCHITECTURE.md for the full diagram and module-by-module breakdown. In short:

Network Traffic → Packet Capture (Scapy) → Rule-Based Detection Engine
                                                     ↓
                          Alert & Logging  ←──────────┤──────────→  Packet-Rate Graph
                                 ↓                                        ↓
                                          Tkinter Dashboard
Detection rules
Rule	Condition (per source IP, per time window)	Attack type
High Traffic	> 100 packets	DoS
Port Scan	> 10 distinct destination ports	Port scanning
SYN Flood	> 50 SYN packets	TCP flood
ICMP Flood	> 50 ICMP packets	Ping flood
DNS Attack	> 80 UDP/53 packets	DNS amplification
Brute Force	> 20 connection attempts	Repeated login attempts
Full rationale and tuning guidance: docs/RULES.md.

Repository structure
CyberWatch-IDS/
├── main.py                  # entry point (login → dashboard)
├── config.py                # thresholds, interface, credentials, paths
├── requirements.txt
├── src/
│   ├── auth.py               # login screen (demo-only auth)
│   ├── capture.py             # Scapy packet sniffing
│   ├── detection.py           # rule-based detection engine (GUI-free, testable)
│   ├── logging_utils.py       # alert logging + CSV export
│   ├── visualization.py       # embedded packet-rate graph
│   └── gui.py                 # Tkinter dashboard, wires everything together
├── tests/
│   └── test_detection.py      # unit tests for the rule engine
├── data/
│   └── sample_logs.csv        # small real sample from an actual test run
├── docs/
│   ├── ARCHITECTURE.md
│   └── RULES.md
└── logs/                       # created at runtime (git-ignored)
Installation
Requires Python 3.9+. Packet capture requires elevated/administrator privileges on every OS, plus a packet-capture driver on Windows.

git clone https://github.com/<your-username>/CyberWatch-IDS.git
cd CyberWatch-IDS
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
Linux — Tkinter isn't always bundled with Python:

sudo apt install python3-tk
Windows — Scapy needs Npcap installed (check "Install Npcap in WinPcap API-compatible mode" during setup).

macOS — Tkinter ships with the python.org installer; if you used Homebrew Python you may need brew install python-tk.

Usage
Run with elevated privileges, since raw packet capture requires it everywhere:

sudo python3 main.py      # Linux / macOS
# Windows: run your terminal "as Administrator", then
python main.py
Log in (demo credentials — see Security Notes).
Click Start to begin capturing on the configured interface.
Watch live traffic and alerts in the log panel.
Click Graph for a live packets/sec view, Export CSV to save alerts for analysis, Clear Logs to reset the on-screen view (this does not erase logs/logs.txt).
Configuration
Everything tunable lives in config.py, and most of it can be overridden via environment variables without editing the file:

Variable	Default	Purpose
CYBERWATCH_IFACE	auto-detected	Network interface to sniff (e.g. eth0, en0, "Wi-Fi")
CYBERWATCH_LOG_DIR	logs	Where logs.txt / logs.csv are written
CYBERWATCH_USER	admin	Demo login username
CYBERWATCH_PASS	1234	Demo login password
Detection thresholds and the TIME_WINDOW are edited directly in config.py — see docs/RULES.md for guidance.

Testing
The detection engine has no networking or GUI dependency, so its test suite runs anywhere:

pip install pytest
pytest tests/ -v
Security notes
This project was built for educational demonstration, not production deployment. Before using it anywhere beyond a lab/classroom:

The login screen is not real authentication. It's a Tkinter form checking a plaintext string comparison — no hashing, no sessions, no rate limiting. Treat it as a UI placeholder. Set CYBERWATCH_USER / CYBERWATCH_PASS at minimum, and don't expose this app to untrusted users as-is.
Raw packet capture requires root/admin. Only run this on a machine and network you're authorized to monitor.
No payload inspection — by design, for privacy — which also means CyberWatch cannot detect attacks that only reveal themselves in payload content (e.g. SQL injection strings, malware signatures).
Known issues we found in our own logs
data/sample_logs.csv is a small excerpt from a real test run. The full original log (logs.csv, not committed — see .gitignore) contained 201,085 alert rows from a single test session:

Alert type	Count
High Traffic	148,570
Port Scanning	41,071
Brute Force	11,256
DNS Attack	183
A handful of source IPs accounted for the overwhelming majority of these (one IP alone produced 56,395 "High Traffic" alerts). This is a symptom of alert flooding: once a per-IP counter crosses a threshold, the rule re-fires on every single subsequent packet from that IP until the next reset_counters() sweep. On a sustained flood, that can mean thousands of duplicate alerts for what is really one ongoing event.

This refactor doesn't change that fundamental behavior (it faithfully reproduces the rule semantics from the original code), but it's worth knowing before you rely on the alert count as a severity signal. A natural follow-up (see Roadmap) is de-duplicating consecutive identical alerts per IP, or only alerting once per time window instead of once per packet.

What changed from the original prototype
The original Cyb.py was a single ~200-line script mixing GUI, packet capture, detection, and logging together. Functionality is preserved, with these fixes/improvements:

Split into modules (capture / detection / logging_utils / visualization / gui / auth) so the detection logic can be unit tested independently of Scapy or Tkinter.
Fixed a GUI freeze: the original "Graph" button ran an infinite while True: plt.pause(1) loop directly on the Tkinter callback thread, which blocked the entire dashboard the moment it was clicked. The graph is now embedded via FigureCanvasTkAgg and redraws itself using root.after(...), so it no longer blocks the event loop.
Configurable network interface instead of a hardcoded "en0" (macOS-only), via CYBERWATCH_IFACE / auto-detection.
Credentials moved out of source into environment-variable-backed config (still a demo login, see Security Notes).
Sniffing now actually stops when you click Stop, via Scapy's stop_filter, instead of only suppressing GUI updates while the background thread kept capturing.
Timestamped log entries instead of bare event strings.
Roadmap
From the original project report's future-work section, plus findings from this refactor:

 De-duplicate/rate-limit repeated identical alerts (see Known Issues)
 Machine-learning-based anomaly detection for unknown/zero-day patterns
 Web-based dashboard for remote monitoring
 Real-time email/SMS notifications
 Store logs in a database instead of flat files
 Multi-interface monitoring
 Advanced attack classification (DDoS, phishing traffic, malware C2)
License
Released under the MIT License.

References
See docs/ and the original project report for the full literature review. Key prior work referenced during design: Denning's foundational IDS model (1987), Snort's signature-based approach (Roesch, 1999), the DARPA IDS evaluation (Lippmann et al., 2000), critiques of ML-based IDS practicality (Sommer & Paxson, 2010), a survey of data-mining approaches to intrusion detection (Buczak & Guven, 2016), and the CICIDS2017 dataset (Sharafaldin et al., 2018).

