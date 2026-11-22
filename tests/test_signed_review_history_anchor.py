"""Detached Ed25519 history witness: positive and adversarial checks."""
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
spec = importlib.util.spec_from_file_location("review_history_witness", ROOT / "tools" / "signed_review_history_anchor.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedReviewHistoryAnchorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "history.sqlite"
        self.issuer = "a" * 64
        self.reviewer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))  # TEST ONLY
        pub = self.reviewer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.witness_id = hashlib.sha256(pub).hexdigest()
        self.roots = {self.witness_id: pub}
        self.first = mod.history._hash(self.issuer, 1, 1, "b"*64, mod.history.GENESIS)
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            mod.history._schema(conn)
            conn.execute("""
                INSERT INTO review_checkpoint_history VALUES (?,?,?,?,?,?)
            """, (self.issuer, 1, 1, "b"*64, mod.history.GENESIS, self.first))
            conn.commit()

    def envelope(self, entries=1, count=1, head=None):
        body = {"schema_version": "0.1.0", "history_issuer_key_id": self.issuer,
                "entries": entries, "record_count": count,
                "history_head_sha256": self.first if head is None else head}
        signature = self.reviewer.sign(mod.DOMAIN + mod.canonical_anchor(body))
        return {"anchor": body, "witness_key_id": self.witness_id,
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, envelope=None, minimum=1, roots=None, revoked=None):
        report = mod.verify(self.db, self.envelope() if envelope is None else envelope,
                            self.roots if roots is None else roots,
                            set() if revoked is None else revoked, minimum)
        self.assertEqual(report["release_gate"], "HOLD")
        self.assertFalse(report["authorization_granted"])
        self.assertFalse(report["recovery_approved"])
        self.assertFalse(report["automatic_restore"])
        return report

    def test_signed_witness_pending_review_only(self):
        self.assertTrue(self.check()["anchor_valid"])

    def test_unknown_witness_rejected(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-witness")

    def test_revoked_witness_rejected(self):
        self.assertEqual(self.check(revoked={self.witness_id})["reason"], "witness-key-revoked")

    def test_signature_corruption_rejected(self):
        env = self.envelope()
        env["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(env)["reason"], "invalid-anchor-signature")

    def test_signed_body_mutation_rejected(self):
        env = self.envelope()
        env["anchor"]["history_head_sha256"] = "f" * 64
        self.assertEqual(self.check(env)["reason"], "invalid-anchor-signature")

    def test_missing_local_file_fail_closed(self):
        env = self.envelope()
        self.db.unlink()
        self.assertEqual(self.check(env)["reason"], "missing-history-db")
        self.assertFalse(self.db.exists())

    def test_changed_history_detected(self):
        env = self.envelope()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE review_checkpoint_history SET event_hash=?", ("f"*64,))
        self.assertEqual(self.check(env)["reason"], "history-integrity-failed")

    def test_external_minimum_blocks_stale(self):
        self.assertEqual(self.check(minimum=2)["reason"], "stale-anchor")

    def test_same_hash_but_claimed_extra_entries_denied(self):
        env = self.envelope(entries=2, count=2)
        self.assertEqual(self.check(env)["reason"], "history-anchor-state-mismatch")

    def test_bad_record_count_schema_denied(self):
        env = self.envelope()
        env["anchor"]["record_count"] = True
        self.assertEqual(self.check(env)["reason"], "invalid-anchor-record-count")

    def test_unknown_authority_field_denied(self):
        env = self.envelope()
        env["grant"] = True
        self.assertEqual(self.check(env)["reason"], "invalid-anchor-envelope")

    def test_invalid_revocation_set_denied(self):
        self.assertEqual(self.check(revoked={"not-a-key"})["reason"], "invalid-revocation-policy")

    def test_no_trusted_floor_denied(self):
        self.assertEqual(self.check(minimum=None)["reason"], "missing-trusted-minimum-entries")

    def test_newer_local_state_cannot_match_old_anchor(self):
        env = self.envelope()
        tail = mod.history._hash(self.issuer, 2, 2, "c"*64, self.first)
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO review_checkpoint_history VALUES (?,?,?,?,?,?)",
                         (self.issuer, 2, 2, "c"*64, self.first, tail))
        self.assertEqual(self.check(env)["reason"], "external-history-head-mismatch")


if __name__ == "__main__":
    unittest.main()
