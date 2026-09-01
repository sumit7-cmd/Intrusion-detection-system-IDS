# Detection Rules

CyberWatch uses six threshold-based rules, evaluated per source IP over a
rolling `TIME_WINDOW` (default 10 seconds, `config.py`). All thresholds
below are the values shipped in `config.py` and can be edited without
touching any detection code.

| Rule | Condition | Attack type indicated |
|---|---|---|
| High Traffic | more than **100** packets from one IP in the window | Denial of Service (DoS) |
| Port Scan | more than **10** distinct destination ports contacted | Reconnaissance / port scanning |
| SYN Flood | more than **50** TCP SYN packets from one IP | TCP resource-exhaustion flood |
| ICMP Flood | more than **50** ICMP packets from one IP | Ping flood |
| DNS Attack | more than **80** UDP packets to port 53 from one IP | DNS amplification / reflection |
| Brute Force | more than **20** total connection attempts from one IP | Repeated login / brute-force attempts |

## Design notes

- **Header-only, privacy-safe.** Only `IP.src`, `IP.dst`, protocol, destination
  port, and the TCP SYN flag are read. No payload is ever inspected.
- **Local traffic is ignored.** Any source IP starting with `127.`,
  `192.168.`, or `10.` is skipped so the engine focuses on external
  (north-south) traffic rather than LAN chatter.
- **Rules re-arm on reset.** Counters are cleared every `TIME_WINDOW`
  seconds. This is what stops a single rule from firing on *every*
  subsequent packet once its threshold is crossed — see the
  [Known Issues](../README.md#known-issues-we-found-in-our-own-logs)
  section in the README for what happens without a fast-enough reset
  relative to a sustained flood.
- **No behavioural memory across resets.** Because state is cleared
  completely, a slow, low-and-slow attack that stays just under a
  threshold within every single window will never trigger an alert. This
  is a known limitation of simple rule-based / threshold IDS approaches
  (see literature review in `IDS.pdf`, Chapter 2) and is one motivation
  for the "Future Work" item on integrating ML-based anomaly detection.

## Tuning thresholds

Edit `THRESHOLDS` and `TIME_WINDOW` in `config.py`. Lower thresholds make
the IDS more sensitive (more alerts, more false positives); higher
thresholds make it quieter (fewer alerts, more chance of missing a real
attack). There is no universally "correct" value — it depends on your
network's normal baseline traffic.
