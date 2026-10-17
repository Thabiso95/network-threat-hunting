import unittest
from pathlib import Path


class InvestigationOutcomeReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "sample-investigation-outcomes.md"
        )
        cls.content = cls.path.read_text(encoding="utf-8")
        cls.normalised = " ".join(cls.content.split())

    def test_report_exists_and_references_case(self):
        self.assertTrue(self.path.is_file())
        self.assertIn("NTH-001-CASE-002", self.content)

    def test_both_alternative_outcomes_are_documented(self):
        self.assertIn("Outcome A", self.content)
        self.assertIn("Outcome B", self.content)
        self.assertIn("Benign", self.content)
        self.assertIn("Pending", self.content)

    def test_hypothetical_evidence_is_not_misrepresented(self):
        self.assertIn("hypothetical", self.content.lower())
        self.assertIn("Live investigation performed:** No", self.content)
        self.assertIn(
            "They have not been independently verified",
            self.normalised,
        )

    def test_report_preserves_evidence_based_decision_making(self):
        self.assertIn(
            "This is a detection signal, not proof of data theft.",
            self.normalised,
        )
        self.assertIn("No unresolved material contradictions", self.content)
        self.assertIn(
            "Missing evidence is not proof of malicious activity",
            self.normalised,
        )

    def test_unresolved_case_stays_open_pending_evidence(self):
        self.assertIn("Malicious exfiltration is", self.content)
        self.assertIn(
            "case remains open pending additional evidence",
            self.normalised,
        )
        self.assertIn("Decision criteria", self.content)


if __name__ == "__main__":
    unittest.main()
