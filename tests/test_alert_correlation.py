import unittest
import pandas as pd

from src.correlate_alerts import correlate_alerts


class AlertCorrelationTests(unittest.TestCase):
    def make_alerts(self):
        return pd.DataFrame([
            {
                "finding_type": "High-transfer event",
                "source_ip": "192.0.2.70",
                "destination_ip": "198.51.100.90",
                "timestamp": "2026-10-15T09:06:30Z",
                "severity": "Medium - provisional",
                "bytes_sent": 950000,
            },
            {
                "finding_type": "High-transfer event",
                "source_ip": "192.0.2.70",
                "destination_ip": "198.51.100.90",
                "timestamp": "2026-10-15T09:06:35Z",
                "severity": "Medium - provisional",
                "bytes_sent": 970000,
            },
            {
                "finding_type": "Cumulative high-transfer activity",
                "source_ip": "192.0.2.70",
                "destination_ip": "198.51.100.90",
                "timestamp": "2026-10-15T09:06:30Z",
                "severity": "Medium - provisional",
                "bytes_sent": 2910000,
            },
            {
                "finding_type": "Potential port scan",
                "source_ip": "192.0.2.50",
                "destination_ip": "198.51.100.60",
                "timestamp": "2026-10-15T09:05:00Z",
                "severity": "Medium - provisional",
                "bytes_sent": None,
            },
        ])

    def test_related_transfer_alerts_share_one_case(self):
        correlated, cases = correlate_alerts(self.make_alerts())
        transfer = correlated[
            correlated["source_ip"] == "192.0.2.70"
        ]
        self.assertEqual(transfer["case_id"].nunique(), 1)
        self.assertEqual(len(transfer), 3)

    def test_unrelated_source_destination_pair_gets_separate_case(self):
        correlated, cases = correlate_alerts(self.make_alerts())
        self.assertEqual(correlated["case_id"].nunique(), 2)
        self.assertEqual(len(cases), 2)

    def test_overlapping_transfer_detections_are_disclosed(self):
        correlated, cases = correlate_alerts(self.make_alerts())
        transfer_case = cases[
            cases["source_ip"] == "192.0.2.70"
        ].iloc[0]
        self.assertTrue(transfer_case["overlapping_detections"])
        self.assertIn("do not treat their byte counts as separate traffic",
                      transfer_case["case_summary"])

    def test_alerts_outside_window_get_separate_cases(self):
        alerts = self.make_alerts().iloc[[0, 1]].copy()
        alerts.loc[1, "timestamp"] = "2026-10-15T09:08:00Z"
        correlated, cases = correlate_alerts(alerts, window_seconds=60)
        self.assertEqual(correlated["case_id"].nunique(), 2)
        self.assertEqual(len(cases), 2)

    def test_input_alerts_are_not_modified(self):
        alerts = self.make_alerts()
        original_columns = list(alerts.columns)
        original_rows = len(alerts)
        correlate_alerts(alerts)
        self.assertEqual(list(alerts.columns), original_columns)
        self.assertEqual(len(alerts), original_rows)

    def test_empty_alerts_return_empty_results(self):
        alerts = self.make_alerts().iloc[0:0].copy()
        correlated, cases = correlate_alerts(alerts)
        self.assertEqual(len(correlated), 0)
        self.assertEqual(len(cases), 0)


if __name__ == "__main__":
    unittest.main()
