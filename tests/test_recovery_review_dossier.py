"""Negative/positive recovery dossier integrity and authority checks."""
import base64
import copy
import hashlib
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "dossier", ROOT / "tools" / "recovery_review_dossier.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RecoveryDossierTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.evidence = Path(temp.name) / "evidence.sqlite"
        self.store = Path(temp.name) / "checkpoint.sqlite"
        issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))  # TEST ONLY
        pub = issuer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(pub).hexdigest()
        self.roots = {self.key_id: pub}
        with sqlite3.connect(self.evidence) as db:
            db.execute("BEGIN IMMEDIATE")
            mod.assessment.checkpoint.audit.append(db, "registry-revision", "issuer-a", "revision-1")
            db.commit()
        details = mod.assessment.checkpoint.audit.verify(self.evidence)
        body = {"schema_version": "0.1.0",
                "sequence": details["events_checked"], "head_hash": details["head_hash"]}
        signed = issuer.sign(mod.assessment.checkpoint.DOMAIN
                             + mod.assessment.checkpoint.canonical_checkpoint(body))
        self.witness = {"checkpoint": body, "issuer_key_id": self.key_id,
                        "signature_b64": base64.b64encode(signed).decode()}
        check = mod.assessment.registry.record(self.store, self.evidence, self.witness,
                                               self.roots, set(), 1)
        self.assertTrue(check["checkpoint_recorded"])
        self.review = {"reviewer_id": "reviewer-a", "decision": "request-review",
                       "reason": "Independent security verification required",
                       "reviewed_at_utc": "2026-11-22T05:00:00Z"}

    def make(self, **kwargs):
        result = mod.prepare_dossier(
            self.evidence, self.store, self.witness, self.roots, set(), 1,
            kwargs.get("review", self.review)
        )
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_verified_dossier_still_hold(self):
        result = self.make()
        self.assertEqual(result["dossier"]["assessment_state"], "pending-review")
        self.assertTrue(mod.verify_dossier(result["dossier"], result["dossier_sha256"]))

    def test_identical_input_deterministic_digest(self):
        self.assertEqual(self.make()["dossier_sha256"], self.make()["dossier_sha256"])

    def test_report_tamper_detected(self):
        r = self.make()
        item = copy.deepcopy(r["dossier"])
        item["manual_review"]["reason"] = "forged"
        self.assertFalse(mod.verify_dossier(item, r["dossier_sha256"]))

    def test_extra_approval_field_not_accepted(self):
        r = self.make()
        item = copy.deepcopy(r["dossier"])
        item["approved"] = True
        self.assertFalse(mod.verify_dossier(item, r["dossier_sha256"]))

    def test_approve_decision_rejected(self):
        review = {**self.review, "decision": "approve"}
        with self.assertRaisesRegex(ValueError, "unsupported-review-decision"):
            self.make(review=review)

    def test_missing_reviewer_id_rejected(self):
        review = {**self.review, "reviewer_id": ""}
        with self.assertRaisesRegex(ValueError, "invalid-reviewer-id"):
            self.make(review=review)

    def test_invalid_timestamp_rejected(self):
        review = {**self.review, "reviewed_at_utc": "2026-11-22T06:00:00+01:00"}
        with self.assertRaisesRegex(ValueError, "invalid-review-time"):
            self.make(review=review)

    def test_forged_future_timestamp_no_authority(self):
        review = {**self.review, "reviewed_at_utc": "2030-01-01T00:00:00Z"}
        self.assertFalse(self.make(review=review)["authorization_granted"])

    def test_quarantine_produces_investigation_report(self):
        self.store.unlink()
        result = self.make()
        self.assertEqual(result["dossier"]["assessment_state"], "quarantined")
        self.assertEqual(result["dossier"]["required_follow_up"], "investigate-and-quarantine")
        self.assertFalse(self.store.exists())

    def test_review_mutation_does_not_mutate_input(self):
        original = copy.deepcopy(self.review)
        self.make()
        self.assertEqual(self.review, original)

    def test_different_decisions_change_digest(self):
        first = self.make()["dossier_sha256"]
        second = self.make(review={**self.review, "decision": "defer"})["dossier_sha256"]
        self.assertNotEqual(first, second)

    def test_invalid_hash_rejected(self):
        self.assertFalse(mod.verify_dossier(self.make()["dossier"], "abc"))

    def test_no_file_writes_for_missing_databases(self):
        self.store.unlink()
        self.evidence.unlink()
        report = self.make()
        self.assertEqual(report["dossier"]["assessment_state"], "quarantined")
        self.assertFalse(self.store.exists())
        self.assertFalse(self.evidence.exists())


if __name__ == "__main__":
    unittest.main()
