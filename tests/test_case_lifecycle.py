import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.manage_cases import initialize_register, update_case


def prioritized_input():
    return pd.DataFrame([
        {
            "case_id": "CASE-001",
            "source_ip": "192.0.2.50",
            "destination_ip": "198.51.100.60",
            "priority_score": 30,
            "priority": "Medium",
        },
        {
            "case_id": "CASE-002",
            "source_ip": "192.0.2.70",
            "destination_ip": "198.51.100.90",
            "priority_score": 69,
            "priority": "High",
        },
    ])


class CaseLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.register = root / "case-register.csv"
        self.audit = root / "case-audit-log.csv"
        initialize_register(
            prioritized_input(), self.register, self.audit
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_initial_register_opens_all_cases(self):
        register = pd.read_csv(self.register)
        self.assertEqual(len(register), 2)
        self.assertTrue((register["status"] == "Open").all())
        self.assertTrue((register["disposition"] == "Pending").all())

    def test_new_cases_are_audited(self):
        audit = pd.read_csv(self.audit)
        self.assertEqual(len(audit), 2)
        self.assertTrue((audit["action"] == "CASE_REGISTERED").all())

    def test_initialisation_does_not_duplicate_cases(self):
        initialize_register(
            prioritized_input(), self.register, self.audit
        )
        register = pd.read_csv(self.register)
        audit = pd.read_csv(self.audit)
        self.assertEqual(len(register), 2)
        self.assertEqual(len(audit), 2)

    def test_update_changes_status_and_appends_audit(self):
        update_case(
            "CASE-001", self.register, self.audit,
            analyst="SOC Analyst",
            status="Investigating",
            evidence_reviewed="Synthetic network-traffic.csv",
            analyst_notes="Reviewing destination-port pattern.",
            reason="Initial evidence review started.",
        )
        register = pd.read_csv(self.register)
        audit = pd.read_csv(self.audit)
        row = register[register["case_id"] == "CASE-001"].iloc[0]
        self.assertEqual(row["status"], "Investigating")
        self.assertEqual(len(audit), 3)
        self.assertEqual(audit.iloc[-1]["analyst"], "SOC Analyst")

    def test_closing_without_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            update_case(
                "CASE-001", self.register, self.audit,
                status="Closed",
                disposition="Benign",
                analyst_notes="Looks routine.",
                reason="Attempted closure.",
            )

    def test_closing_with_pending_disposition_is_rejected(self):
        with self.assertRaises(ValueError):
            update_case(
                "CASE-001", self.register, self.audit,
                status="Closed",
                evidence_reviewed="Synthetic evidence reviewed.",
                analyst_notes="Review complete.",
                reason="Attempted closure.",
            )

    def test_update_requires_reason(self):
        with self.assertRaises(ValueError):
            update_case(
                "CASE-001", self.register, self.audit,
                status="Investigating",
            )

    def test_invalid_status_is_rejected(self):
        with self.assertRaises(ValueError):
            update_case(
                "CASE-001", self.register, self.audit,
                status="Attack confirmed",
                reason="Testing invalid status.",
            )


if __name__ == "__main__":
    unittest.main()
