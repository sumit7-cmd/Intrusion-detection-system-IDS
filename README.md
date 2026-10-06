# 🛡️ CyberWatch IDS

**Real-Time Network Intrusion Detection System** built with **Python, Scapy, Tkinter, rule-based detection, logging, and visualization**.

CyberWatch monitors authorized network traffic, extracts packet metadata, evaluates configurable behavioral thresholds, and surfaces alerts through a desktop dashboard. The detection engine is isolated from packet capture and GUI code so it can be tested in headless CI environments.

## Key capabilities

- Real-time packet capture with Scapy
- Header-focused packet feature extraction
- Threshold-based network anomaly detection
- Per-source-IP state tracking
- Alert deduplication within the active window
- Severity-aware alerts
- CSV and text logging
- Configurable interface and thresholds
- Tkinter dashboard and traffic visualization
- Detection-engine tests that do not require root privileges
- GitHub Actions CI

## Detection rules

| Rule | Default signal | Severity |
|---|---|---|
| HIGH-TRAFFIC | >100 packets from a source in the active window | High |
| PORT-SCAN | >10 distinct destination ports | High |
| SYN-FLOOD | >50 SYN packets | Critical |
| ICMP-FLOOD | >50 ICMP packets | High |
| DNS-ATTACK | >80 UDP/53 packets | Medium |
| BRUTE-FORCE | >20 TCP connection attempts | High |

Thresholds should be tuned for the network baseline rather than treated as universal attack signatures.

## Architecture

```text
Network Traffic
      |
      v
Scapy Capture
      |
      v
Packet Features
      |
      v
Detection Engine
      |
      v
Alert + Deduplication
   /          \
  v            v
Logs / CSV   Tkinter UI
```

## Project structure

```text
.
├── main.py
├── config.py
├── requirements
├── src/
│   ├── __init__.py
│   ├── auth.py
│   ├── capture.py
│   ├── detection.py
│   ├── gui.py
│   ├── logging_utils.py
│   └── visualization.py
├── tests/
│   ├── __init__.py
│   └── test_detection.py
├── docs/
│   ├── ARCHITECTURE.md
│   └── RULES.md
├── .github/workflows/ci.yml
├── .env.example
├── SECURITY.md
└── logs/  # runtime output, not source-controlled
```

## Installation

Requires Python 3.9+.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows
.venv\\Scripts\\activate
python -m pip install -r requirements
```

Linux may require Tkinter separately:

```bash
sudo apt install python3-tk
```

Windows packet capture requires a compatible capture driver such as Npcap.

## Usage

Run the application according to your packet-capture privileges:

```bash
python main.py
```

Configure the capture interface and thresholds before monitoring a network you are authorized to inspect.

## Testing

The detection engine is deliberately independent from live capture and the GUI:

```bash
python -m pip install pytest
PYTHONPATH=. python -m pytest -q
```

The GitHub Actions workflow runs these tests on every push and pull request.

## SOC relevance

This project demonstrates network monitoring, alert generation, source-IP investigation, behavior-based detection, severity classification, evidence logging, detection tuning, Python automation, and testing discipline.

## Limitations

This is an educational IDS, not a replacement for mature NIDS platforms. Threshold-based rules may create false positives and can miss attacks requiring payload inspection, protocol-aware parsing, multi-host correlation, or deeper behavioral analysis.

## Roadmap

- PCAP replay for offline testing
- JSON/SIEM-friendly event output
- Sliding-window detection
- Database-backed event storage
- Prometheus metrics
- Web dashboard
- MITRE ATT&CK technique mapping
- Additional protocol-aware detectors
- ML-assisted anomaly scoring
- Alert suppression and escalation policies

## Security

Only monitor traffic you are legally authorized to inspect. See SECURITY.md.

## License

MIT
