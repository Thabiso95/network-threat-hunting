import unittest
from pathlib import Path


class EvidenceCollectionChecklistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "evidence-collection-checklist.md"
        )
        cls.content = cls.path.read_text(encoding="utf-8")

    def test_checklist_exists_and_has_case_reference(self):
        self.assertTrue(self.path.is_file())
        self.assertIn("NTH-001-CASE-002", self.content)

    def test_case_remains_investigating_and_pending(self):
        self.assertIn("**Status:** Investigating", self.content)
        self.assertIn("**Disposition:** Pending", self.content)

    def test_covers_core_evidence_categories(self):
        for phrase in (
            "destination ownership",
            "business authorisation",
            "network and application evidence",
            "endpoint evidence",
            "repeated activity",
            "Document, preserve and escalate",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.content)

    def test_distinguishes_synthetic_evidence_from_live_activity(self):
        self.assertIn("Synthetic training data", self.content)
        self.assertIn("Live environment queried:** No", self.content)
        self.assertIn("Malicious exfiltration remains unconfirmed", self.content)

    def test_does_not_treat_threshold_as_proof(self):
        self.assertIn(
            "A detection threshold is a triage signal, not proof of malicious activity.",
            self.content,
        )


if __name__ == "__main__":
    unittest.main()
