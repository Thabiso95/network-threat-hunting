from pathlib import Path
import sys
import unittest
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hunt_network import detect_cumulative_transfers


def make_transfer_events(byte_values, seconds_between=10):
    start = pd.Timestamp("2026-10-15T10:00:00Z")
    return pd.DataFrame([
        {
            "timestamp": start + pd.Timedelta(seconds=i * seconds_between),
            "source_ip": "192.0.2.210",
            "destination_ip": "198.51.100.210",
            "destination_port": 8080,
            "protocol": "TCP",
            "connection_state": "ESTABLISHED",
            "bytes_sent": value,
        }
        for i, value in enumerate(byte_values)
    ])


class CumulativeTransferTests(unittest.TestCase):
    def test_detects_multiple_smaller_transfers_over_threshold(self):
        # No individual event reaches 900,000 bytes, but the total is 2.55 MB.
        events = make_transfer_events([850_000, 850_000, 850_000])
        findings = detect_cumulative_transfers(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings.iloc[0]["finding_type"],
            "Cumulative high-transfer activity"
        )
        self.assertEqual(int(findings.iloc[0]["bytes_sent"]), 2_550_000)
        self.assertEqual(int(findings.iloc[0]["event_count"]), 3)

    def test_does_not_flag_total_below_threshold(self):
        events = make_transfer_events([500_000, 500_000, 500_000])
        findings = detect_cumulative_transfers(events)
        self.assertTrue(findings.empty)

    def test_detects_threshold_after_earlier_event_expires(self):
        import pandas as pd
        from src.hunt_network import detect_cumulative_transfers

        events = pd.DataFrame({
            "timestamp": pd.to_datetime([
                "2026-10-16T10:00:00Z",
                "2026-10-16T10:01:10Z",
                "2026-10-16T10:01:15Z",
            ], utc=True),
            "source_ip": ["192.0.2.70"] * 3,
            "destination_ip": ["198.51.100.90"] * 3,
            "destination_port": [8080] * 3,
            "protocol": ["TCP"] * 3,
            "connection_state": ["ESTABLISHED"] * 3,
            "bytes_sent": [900_000, 1_300_000, 1_300_000],
        })

        alerts = detect_cumulative_transfers(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(int(alerts.iloc[0]["bytes_sent"]), 2_600_000)
        self.assertEqual(int(alerts.iloc[0]["event_count"]), 2)

    def test_does_not_combine_events_outside_window(self):
        # The events span 80 seconds, so no 60-second window contains all three.
        events = make_transfer_events(
            [900_000, 900_000, 900_000], seconds_between=40
        )
        findings = detect_cumulative_transfers(events)
        self.assertTrue(findings.empty)


if __name__ == "__main__":
    unittest.main()
