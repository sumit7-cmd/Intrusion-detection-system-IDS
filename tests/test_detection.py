from src.detection import DetectionEngine, PacketFeatures


def test_high_traffic_alert():
    engine = DetectionEngine({"high_traffic": 2})
    alerts = []
    for _ in range(3):
        alerts.extend(engine.process(PacketFeatures("10.0.0.10", "TCP", 1000, 443, "A")))
    assert any(a.rule_id == "HIGH-TRAFFIC" for a in alerts)


def test_port_scan_alert():
    engine = DetectionEngine({"port_scan": 2})
    alerts = []
    for port in (22, 80, 443):
        alerts.extend(engine.process(PacketFeatures("10.0.0.20", "TCP", 4000, port, "S")))
    assert any(a.rule_id == "PORT-SCAN" for a in alerts)


def test_syn_flood_alert():
    engine = DetectionEngine({"syn_flood": 2})
    alerts = []
    for _ in range(3):
        alerts.extend(engine.process(PacketFeatures("10.0.0.30", "TCP", 4000, 443, "S")))
    assert any(a.rule_id == "SYN-FLOOD" for a in alerts)


def test_no_duplicate_alerts():
    engine = DetectionEngine({"high_traffic": 1})
    results = []
    for _ in range(5):
        results.extend(engine.process(PacketFeatures("10.0.0.40", "TCP", 1, 80, "A")))
    assert len([a for a in results if a.rule_id == "HIGH-TRAFFIC"]) == 1
