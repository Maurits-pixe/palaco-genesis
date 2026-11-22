"""Fail-closed tests for the proposed offline evidence recovery state policy."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("offline_policy", ROOT / "tools" / "validate_offline_recovery.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class OfflineRecoveryPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads(
            (ROOT / "ecosystem" / "offline-recovery-policy.v0.1.json").read_text(encoding="utf-8")
        )

    def candidate(self):
        return copy.deepcopy(self.policy)

    def rejects(self, data, fragment):
        errors = validator.validate(data)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_valid_policy(self):
        self.assertEqual(validator.validate(self.candidate()), [])

    def test_release_cannot_advance(self):
        data = self.candidate()
        data["release_gate"] = "GO"
        self.rejects(data, "HOLD")

    def test_runtime_cannot_activate(self):
        data = self.candidate()
        data["runtime_enabled"] = True
        self.rejects(data, "disabled runtime")

    def test_offline_trust_elevation_rejected(self):
        data = self.candidate()
        data["allowed_states"].append("verified")
        self.rejects(data, "state set")

    def test_quarantine_escape_rejected(self):
        data = self.candidate()
        data["allowed_transitions"].append({
            "from": "quarantined", "to": "pending-review", "requires": "local-approval"
        })
        self.rejects(data, "transition set")

    def test_auto_authorization_must_stay_forbidden(self):
        data = self.candidate()
        data["forbidden_offline_actions"].remove("authorize-execution")
        self.rejects(data, "forbidden action set")

    def test_conflict_cannot_auto_merge(self):
        data = self.candidate()
        data["conflict_policy"] = "auto-merge"
        self.rejects(data, "conflict_policy")

    def test_missing_provenance_cannot_be_accepted(self):
        data = self.candidate()
        data["missing_provenance"] = "accept"
        self.rejects(data, "missing_provenance")

    def test_reconciliation_requires_review(self):
        data = self.candidate()
        data["reconciliation"] = "auto"
        self.rejects(data, "reconciliation")

    def test_duplicate_detection_cannot_be_disabled(self):
        data = self.candidate()
        data["duplicate_detection"] = "none"
        self.rejects(data, "duplicate_detection")

    def test_bad_transition_type_rejected(self):
        data = self.candidate()
        data["allowed_transitions"][0]["requires"] = []
        self.rejects(data, "invalid transition")


if __name__ == "__main__":
    unittest.main()
