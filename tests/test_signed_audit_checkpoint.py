"""Adversarial signed audit-checkpoint verifier tests."""
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
spec = importlib.util.spec_from_file_location("audit_checkpoint", ROOT / "tools" / "signed_audit_checkpoint.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedCheckpointTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "audit.sqlite"
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            mod.audit.append(conn, "registry-revision", "issuer-a", "revision-5")
            mod.audit.append(conn, "candidate-indexed", "record-a", "lineage-a")
            conn.commit()
        checked = mod.audit.verify(self.db)
        self.body = {"schema_version": "0.1.0", "sequence": checked["events_checked"],
                     "head_hash": checked["head_hash"]}
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))  # TEST ONLY
        pub = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.fingerprint = hashlib.sha256(pub).hexdigest()
        self.roots = {self.fingerprint: pub}

    def envelope(self, body=None):
        data = copy.deepcopy(self.body if body is None else body)
        sig = self.private.sign(mod.DOMAIN + mod.canonical_checkpoint(data))
        return {"checkpoint": data, "issuer_key_id": self.fingerprint,
                "signature_b64": base64.b64encode(sig).decode()}

    def check(self, envelope=None, roots=None, floor=2):
        result = mod.verify_checkpoint(
            self.db, self.envelope() if envelope is None else envelope,
            self.roots if roots is None else roots, floor)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        return result

    def test_valid_signature_only_pending_review(self):
        verdict = self.check()
        self.assertTrue(verdict["checkpoint_valid"])
        self.assertEqual(verdict["state"], "pending-review")

    def test_unknown_root_denied(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-checkpoint-issuer")

    def test_modified_signed_head_denied(self):
        env = self.envelope()
        env["checkpoint"]["head_hash"] = "a" * 64
        self.assertEqual(self.check(env)["reason"], "invalid-checkpoint-signature")

    def test_modified_signature_denied(self):
        env = self.envelope()
        env["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(env)["reason"], "invalid-checkpoint-signature")

    def test_rollback_floor_denied(self):
        self.assertEqual(self.check(floor=3)["reason"], "stale-checkpoint")

    def test_tampered_local_audit_denied(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE local_audit_chain SET detail='forged' WHERE sequence=2")
        self.assertEqual(self.check()["reason"], "audit-audit-hash-mismatch")

    def test_missing_audit_file_denied(self):
        self.db.unlink()
        self.assertEqual(self.check()["reason"], "audit-missing-database")

    def test_truncated_local_audit_denied(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM local_audit_chain WHERE sequence=2")
        self.assertEqual(self.check()["reason"], "audit-external-head-mismatch")

    def test_same_head_invalid_sequence_rejected(self):
        env = self.envelope({**self.body, "sequence": 1})
        self.assertEqual(self.check(env, floor=1)["reason"], "audit-sequence-mismatch")

    def test_malformed_checkpoint_denied(self):
        env = self.envelope()
        env["checkpoint"]["sequence"] = True
        self.assertEqual(self.check(env)["reason"], "invalid-checkpoint-sequence")

    def test_unexpected_authority_field_rejected(self):
        env = self.envelope()
        env["grant"] = True
        self.assertEqual(self.check(env)["reason"], "invalid-envelope")

    def test_no_floor_denied(self):
        self.assertEqual(self.check(floor=None)["reason"], "missing-trusted-sequence-floor")


if __name__ == "__main__":
    unittest.main()
