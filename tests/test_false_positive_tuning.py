from pathlib import Path
import sys
import unittest
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hunt_network import detect_port_scans


def make_events(seconds_between_ports):
    start = pd.Timestamp("2026-10-15T09:00:00Z")
    rows = []
    for port_index, port in enumerate(
        [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]
    ):
        rows.append({
            "timestamp": start + pd.Timedelta(
                seconds=port_index * seconds_between_ports
            ),
            "source_ip": "192.0.2.200",
            "destination_ip": "198.51.100.200",
            "destination_port": port,
        })
    return pd.DataFrame(rows)


class FalsePositiveTuningTests(unittest.TestCase):
    def test_ten_ports_within_sixty_seconds_trigger(self):
        # Ten distinct ports span 54 seconds.
        findings = detect_port_scans(make_events(6))
        self.assertFalse(findings.empty)
        self.assertGreaterEqual(findings.iloc[0]["unique_ports"], 10)

    def test_ten_ports_spread_across_sixty_three_seconds_do_not_trigger(self):
        # Ten distinct ports span 63 seconds; no 60-second window contains all ten.
        findings = detect_port_scans(make_events(7))
        self.assertTrue(findings.empty)


if __name__ == "__main__":
    unittest.main()
