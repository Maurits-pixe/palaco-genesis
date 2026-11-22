"""Regression tests for local chained signed-review checkpoint history."""
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
spec = importlib.util.spec_from_file_location("history", ROOT / "tools" / "review_checkpoint_history.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CheckpointHistoryTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db = Path(t.name) / "reviews.sqlite"
        self.history = Path(t.name) / "history.sqlite"
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE observed_recovery_reviews(
                dossier_sha256 TEXT NOT NULL, reviewer_id TEXT NOT NULL,
                key_id TEXT NOT NULL, declaration_digest TEXT NOT NULL,
                signature_digest TEXT NOT NULL,
                PRIMARY KEY (dossier_sha256,reviewer_id))""")
            c.execute("INSERT INTO observed_recovery_reviews VALUES (?,?,?,?,?)",
                      ("1"*64, "reviewer-a", "2"*64, "3"*64, "4"*64))
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(11,43)))
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer = hashlib.sha256(public).hexdigest()
        self.roots = {self.issuer: public}

    def witness(self):
        data = mod.checkpoint.snapshot(self.db)
        signature = self.key.sign(mod.checkpoint.DOMAIN + mod.checkpoint.canonical(data))
        return {"checkpoint": data, "issuer_key_id": self.issuer,
                "signature_b64": base64.b64encode(signature).decode()}

    def observe(self, witness=None, minimum=1, revoked=None):
        r = mod.observe(self.history, self.db, self.witness() if witness is None else witness,
                        self.roots, set() if revoked is None else revoked, minimum)
        self.assertFalse(r["authorization_granted"])
        self.assertFalse(r["recovery_approved"])
        self.assertEqual(r["release_gate"], "HOLD")
        return r

    def add(self):
        with sqlite3.connect(self.db) as c:
            c.execute("INSERT INTO observed_recovery_reviews VALUES (?,?,?,?,?)",
                      ("5"*64, "reviewer-a", "2"*64, "3"*64, "4"*64))

    def test_first_observation(self):
        self.assertTrue(self.observe()["history_updated"])

    def test_repeat_is_idempotent(self):
        self.observe()
        self.assertEqual(self.observe()["reason"], "already-observed")

    def test_newer_checkpoint_chain_verifies(self):
        first = self.observe()
        self.add()
        second = self.observe()
        self.assertNotEqual(first["head_hash"], second["head_hash"])
        self.assertTrue(mod.inspect(self.history, self.issuer, second["head_hash"], 2)["history_valid"])

    def test_old_snapshot_rejected_after_new(self):
        first_witness = self.witness()
        self.observe()
        self.add()
        self.observe()
        self.assertFalse(self.observe(first_witness)["history_updated"])

    def test_changed_history_row_detected(self):
        first = self.observe()
        with sqlite3.connect(self.history) as c:
            c.execute("UPDATE review_checkpoint_history SET rows_sha256=?", ("f"*64,))
        self.assertEqual(mod.inspect(self.history, self.issuer, first["head_hash"], 1)["reason"],
                         "history-integrity-failed")

    def test_external_head_mismatch(self):
        self.observe()
        self.assertEqual(mod.inspect(self.history, self.issuer, "f"*64, 1)["reason"],
                         "external-history-head-mismatch")

    def test_deleted_tail_detected_by_anchor(self):
        self.observe()
        self.add()
        second = self.observe()
        with sqlite3.connect(self.history) as c:
            c.execute("DELETE FROM review_checkpoint_history WHERE ordinal=2")
        self.assertEqual(mod.inspect(self.history, self.issuer, second["head_hash"], 2)["reason"],
                         "history-rollback")

    def test_revoked_issuer_does_not_create_history(self):
        self.assertEqual(self.observe(revoked={self.issuer})["reason"], "issuer-revoked")
        self.assertFalse(self.history.exists())

    def test_invalid_signature_no_history(self):
        bad = self.witness()
        bad["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.observe(bad)["reason"], "invalid-checkpoint-signature")
        self.assertFalse(self.history.exists())

    def test_read_only_missing_history(self):
        self.assertEqual(mod.inspect(self.history, self.issuer, "a"*64, 1)["reason"],
                         "missing-history-db")
        self.assertFalse(self.history.exists())

    def test_missing_external_anchor_rejected(self):
        self.observe()
        self.assertEqual(mod.inspect(self.history, self.issuer, None, 1)["reason"],
                         "missing-trusted-history-anchor")

    def test_history_file_different_from_review_db(self):
        with self.assertRaises(ValueError):
            mod.observe(self.db, self.db, self.witness(), self.roots, set(), 1)


if __name__ == "__main__":
    unittest.main()
