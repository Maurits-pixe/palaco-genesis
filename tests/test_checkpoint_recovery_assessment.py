"""Read-only local checkpoint recovery assessment regression tests."""
import base64
import hashlib
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery_assessment", ROOT / "tools" / "checkpoint_recovery_assessment.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CheckpointRecoveryAssessmentTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.evidence = Path(tmp.name) / "evidence.sqlite"
        self.store = Path(tmp.name) / "checkpoint.sqlite"
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))  # TEST ONLY
        public = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer = hashlib.sha256(public).hexdigest()
        self.roots = {self.issuer: public}
        with sqlite3.connect(self.evidence) as db:
            db.execute("BEGIN IMMEDIATE")
            mod.checkpoint.audit.append(db, "registry-revision", "issuer-a", "revision-1")
            db.commit()
        self.witness = self.make_witness()
        result = mod.registry.record(self.store, self.evidence, self.witness, self.roots, set(), 1)
        assert result["checkpoint_recorded"], result

    def make_witness(self):
        report = mod.checkpoint.audit.verify(self.evidence)
        data = {"schema_version": "0.1.0", "sequence": report["events_checked"],
                "head_hash": report["head_hash"]}
        signature = self.signer.sign(mod.checkpoint.DOMAIN + mod.checkpoint.canonical_checkpoint(data))
        return {"checkpoint": data, "issuer_key_id": self.issuer,
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, witness=None, roots=None, revoked=None, minimum=1):
        result = mod.assess(self.evidence, self.store,
                            self.witness if witness is None else witness,
                            self.roots if roots is None else roots,
                            set() if revoked is None else revoked, minimum)
        self.assertIs(result["authorization_granted"], False)
        self.assertIs(result["automatic_restore"], False)
        self.assertIs(result["recovery_approved"], False)
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_matching_records_pending_review(self):
        self.assertEqual(self.check()["state"], "pending-review")

    def test_missing_checkpoint_store_denied(self):
        self.store.unlink()
        self.assertEqual(self.check()["reason"], "checkpoint-missing-database")
        self.assertFalse(self.store.exists())

    def test_missing_evidence_store_denied(self):
        self.evidence.unlink()
        self.assertEqual(self.check()["reason"], "evidence-missing-database")
        self.assertFalse(self.evidence.exists())

    def test_tampered_evidence_chain_denied(self):
        with sqlite3.connect(self.evidence) as db:
            db.execute("UPDATE local_audit_chain SET detail='altered' WHERE sequence=1")
        self.assertEqual(self.check()["reason"], "audit-audit-hash-mismatch")

    def test_deleted_checkpoint_floor_denied(self):
        with sqlite3.connect(self.store) as db:
            db.execute("DELETE FROM checkpoint_floor")
        self.assertEqual(self.check()["reason"], "checkpoint-floor-missing-or-unreadable")

    def test_reduced_floor_sequence_denied(self):
        with sqlite3.connect(self.evidence) as db:
            db.execute("BEGIN IMMEDIATE")
            mod.checkpoint.audit.append(db, "candidate-indexed", "record-b", "lineage-b")
            db.commit()
        newer = self.make_witness()
        self.assertTrue(mod.registry.record(self.store, self.evidence, newer,
                                            self.roots, set(), 1)["checkpoint_recorded"])
        with sqlite3.connect(self.store) as db:
            db.execute("UPDATE checkpoint_floor SET sequence=1")
        self.assertEqual(self.check(witness=newer)["reason"], "checkpoint-store-rollback")

    def test_floor_different_hash_denied(self):
        with sqlite3.connect(self.store) as db:
            db.execute("UPDATE checkpoint_floor SET head_hash=?",
                       ("a" * 64,))
        self.assertEqual(self.check()["reason"], "checkpoint-store-equivocation")

    def test_revoked_issuer_denied(self):
        self.assertEqual(self.check(revoked={self.issuer})["reason"], "witness-issuer-revoked")

    def test_untrusted_issuer_denied(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-checkpoint-issuer")

    def test_external_minimum_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"], "stale-checkpoint")

    def test_changed_signature_denied(self):
        bad = dict(self.witness)
        bad["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(witness=bad)["reason"], "invalid-checkpoint-signature")

    def test_incompatible_newer_floor_denied(self):
        with sqlite3.connect(self.store) as db:
            db.execute("UPDATE checkpoint_floor SET sequence=2")
        self.assertEqual(self.check()["reason"], "witness-older-than-checkpoint-store")

    def test_missing_trust_policy_denied(self):
        self.assertEqual(self.check(revoked=[])["reason"], "missing-trust-policy")

    def test_corrupt_checkpoint_db_denied(self):
        self.store.write_bytes(b"not-a-sqlite-database")
        self.assertIn(self.check()["reason"], {"checkpoint-unreadable-database",
                                               "checkpoint-sqlite-integrity-failed"})


if __name__ == "__main__":
    unittest.main()
