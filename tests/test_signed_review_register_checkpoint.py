"""Signed review replay checkpoint: full state commitment and HOLD tests."""
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
spec = importlib.util.spec_from_file_location("review_checkpoint", ROOT / "tools" / "signed_review_register_checkpoint.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ReviewRegisterCheckpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "reviews.sqlite"
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE observed_recovery_reviews(
                dossier_sha256 TEXT NOT NULL, reviewer_id TEXT NOT NULL,
                key_id TEXT NOT NULL, declaration_digest TEXT NOT NULL,
                signature_digest TEXT NOT NULL,
                PRIMARY KEY (dossier_sha256,reviewer_id))""")
            c.execute("INSERT INTO observed_recovery_reviews VALUES (?,?,?,?,?)",
                      ("1" * 64, "reviewer-a", "2" * 64, "3" * 64, "4" * 64))
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))  # TEST ONLY
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer = hashlib.sha256(public).hexdigest()
        self.roots = {self.issuer: public}

    def envelope(self, data=None):
        body = mod.snapshot(self.db) if data is None else data
        signature = self.private.sign(mod.DOMAIN + mod.canonical(body))
        return {"checkpoint": body, "issuer_key_id": self.issuer,
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, env=None, roots=None, revoked=None, minimum=1):
        report = mod.verify(
            self.db, self.envelope() if env is None else env,
            self.roots if roots is None else roots,
            set() if revoked is None else revoked, minimum)
        self.assertEqual(report["release_gate"], "HOLD")
        self.assertFalse(report["authorization_granted"])
        self.assertFalse(report["recovery_approved"])
        self.assertFalse(report["automatic_restore"])
        return report

    def test_valid_signed_checkpoint_pending(self):
        self.assertTrue(self.check()["checkpoint_valid"])

    def test_modified_record_detected(self):
        env = self.envelope()
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE observed_recovery_reviews SET declaration_digest=?", ("f"*64,))
        self.assertEqual(self.check(env)["reason"], "review-register-hash-mismatch")

    def test_deleted_record_detected(self):
        env = self.envelope()
        with sqlite3.connect(self.db) as c:
            c.execute("DELETE FROM observed_recovery_reviews")
        self.assertEqual(self.check(env)["reason"], "missing-or-unreadable-review-register")

    def test_added_record_detected(self):
        env = self.envelope()
        with sqlite3.connect(self.db) as c:
            c.execute("INSERT INTO observed_recovery_reviews VALUES(?,?,?,?,?)",
                      ("5"*64, "reviewer-a", "2"*64, "3"*64, "4"*64))
        self.assertEqual(self.check(env)["reason"], "review-register-count-mismatch")

    def test_revoked_issuer_denied(self):
        self.assertEqual(self.check(revoked={self.issuer})["reason"], "issuer-revoked")

    def test_unknown_issuer_denied(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-issuer")

    def test_signature_tamper_denied(self):
        env = self.envelope()
        env["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(env)["reason"], "invalid-checkpoint-signature")

    def test_external_floor_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"], "stale-review-register-checkpoint")

    def test_missing_db_no_creation(self):
        self.db.unlink()
        self.assertEqual(self.check(self.envelope({"schema_version":"0.1.0","count":1,
                      "rows_sha256":"1"*64}))["reason"], "missing-or-unreadable-review-register")
        self.assertFalse(self.db.exists())

    def test_invalid_count_boolean_denied(self):
        env = self.envelope()
        env["checkpoint"]["count"] = True
        self.assertEqual(self.check(env)["reason"], "invalid-checkpoint-count")

    def test_extra_field_denied(self):
        env = self.envelope()
        env["authority"] = "grant"
        self.assertEqual(self.check(env)["reason"], "invalid-envelope")

    def test_read_only_snapshot_stable(self):
        self.assertEqual(mod.snapshot(self.db), mod.snapshot(self.db))


if __name__ == "__main__":
    unittest.main()
