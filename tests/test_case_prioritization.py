import sys
import unittest
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.prioritize_cases import prioritize_cases

def sample_cases():
    return pd.DataFrame([
        {
            "case_id": "NTH-001-CASE-001",
            "source_ip": "192.0.2.50",
            "destination_ip": "198.51.100.60",
            "alert_count": 1,
            "finding_types": "Potential port scan",
            "overlapping_detections": False,
        },
        {
            "case_id": "NTH-001-CASE-002",
            "source_ip": "192.0.2.70",
            "destination_ip": "198.51.100.90",
            "alert_count": 4,
            "finding_types": (
                "High-transfer event; Cumulative high-transfer activity"
            ),
            "overlapping_detections": True,
        },
    ])

class CasePrioritisationTests(unittest.TestCase):
    def test_transfer_case_ranks_first(self):
        result = prioritize_cases(sample_cases())
        self.assertEqual(result.iloc[0]["case_id"], "NTH-001-CASE-002")

    def test_transfer_case_is_high_priority(self):
        result = prioritize_cases(sample_cases())
        row = result[result["case_id"] == "NTH-001-CASE-002"].iloc[0]
        self.assertEqual(row["priority"], "High")

    def test_port_scan_is_medium_priority(self):
        result = prioritize_cases(sample_cases())
        row = result[result["case_id"] == "NTH-001-CASE-001"].iloc[0]
        self.assertEqual(row["priority_score"], 30)
        self.assertEqual(row["priority"], "Medium")

    def test_reasons_and_next_steps_are_populated(self):
        result = prioritize_cases(sample_cases())
        self.assertTrue(result["priority_reasons"].str.len().gt(0).all())
        self.assertTrue(
            result["recommended_next_steps"].str.len().gt(0).all()
        )

    def test_input_is_not_modified(self):
        cases = sample_cases()
        columns = list(cases.columns)
        prioritize_cases(cases)
        self.assertEqual(list(cases.columns), columns)

    def test_empty_input(self):
        result = prioritize_cases(sample_cases().iloc[0:0])
        self.assertEqual(len(result), 0)
        self.assertIn("priority", result.columns)

    def test_missing_column_raises_error(self):
        with self.assertRaises(ValueError):
            prioritize_cases(sample_cases().drop(columns=["finding_types"]))

    def test_negative_alert_count_raises_error(self):
        cases = sample_cases()
        cases.loc[0, "alert_count"] = -1
        with self.assertRaises(ValueError):
            prioritize_cases(cases)

if __name__ == "__main__":
    unittest.main()
