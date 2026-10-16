import tempfile
import unittest
from pathlib import Path
import pandas as pd

from src.hunt_network import (
    detect_port_scans,
    detect_high_transfers,
    build_alerts,
    export_alerts,
)


def make_events(ports, byte_values=None):
    if byte_values is None:
        byte_values = [1000] * len(ports)

    return pd.DataFrame({
        "timestamp": pd.to_datetime(
            [f"2026-10-15 09:05:{i:02d}Z" for i in range(len(ports))],
            utc=True
        ),
        "source_ip": ["192.0.2.10"] * len(ports),
        "destination_ip": ["198.51.100.20"] * len(ports),
        "destination_port": ports,
        "protocol": ["TCP"] * len(ports),
        "connection_state": ["SYN_SENT"] * len(ports),
        "bytes_sent": byte_values,
    })


class NetworkHuntingTests(unittest.TestCase):

    def test_detects_port_scan(self):
        events = make_events(list(range(20, 30)))
        findings = detect_port_scans(events)
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(findings.iloc[0]["unique_ports"], 10)

    def test_ignores_fewer_than_ten_ports(self):
        events = make_events([21, 22, 23, 80, 443])
        findings = detect_port_scans(events)
        self.assertTrue(findings.empty)

    def test_detects_high_transfer(self):
        events = make_events([8080], [950000])
        findings = detect_high_transfers(events)
        self.assertEqual(len(findings), 1)

    def test_ignores_ordinary_transfer_size(self):
        events = make_events([8080], [50000])
        findings = detect_high_transfers(events)
        self.assertTrue(findings.empty)

    def test_exports_alerts_to_csv(self):
        events = make_events([8080], [950000])
        alerts = build_alerts(events)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "alerts.csv"
            export_alerts(alerts, output)
            loaded = pd.read_csv(output)

        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded.iloc[0]["finding_type"], "High-transfer event")
        self.assertIn("severity", loaded.columns)
        self.assertIn("recommended_actions", loaded.columns)


if __name__ == "__main__":
    unittest.main()
