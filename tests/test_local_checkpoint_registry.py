"""Test local checkpoint monotonicity and explicit issuer revocation."""
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
spec = importlib.util.spec_from_file_location("checkpoint_store", ROOT / "tools" / "local_checkpoint_registry.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class LocalCheckpointRegistryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "evidence.sqlite"
        self.store = Path(tmp.name) / "checkpoint.sqlite"
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))  # TEST ONLY
        pub = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer = hashlib.sha256(pub).hexdigest()
        self.roots = {self.issuer: pub}
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            mod.checkpoint.audit.append(conn, "registry-revision", "issuer-a", "revision-1")
            conn.commit()
        self.first = self.envelope()

    def envelope(self):
        verified = mod.checkpoint.audit.verify(self.db)
        body = {"schema_version": "0.1.0", "sequence": verified["events_checked"],
                "head_hash": verified["head_hash"]}
        signature = self.private.sign(mod.checkpoint.DOMAIN +
                                      mod.checkpoint.canonical_checkpoint(body))
        return {"checkpoint": body, "issuer_key_id": self.issuer,
                "signature_b64": base64.b64encode(signature).decode()}

    def add_event(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            mod.checkpoint.audit.append(conn, "candidate-indexed", "record-a", "lineage-a")
            conn.commit()

    def check(self, envelope=None, revoked=None, roots=None, minimum=1):
        result = mod.record(
            self.store, self.db, self.first if envelope is None else envelope,
            self.roots if roots is None else roots,
            set() if revoked is None else revoked, minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        return result

    def test_first_checkpoint_persists(self):
        self.assertTrue(self.check()["checkpoint_recorded"])
        self.assertEqual(mod.read_floor(self.store, self.issuer)["sequence"], 1)

    def test_identical_checkpoint_idempotent(self):
        self.check()
        self.assertEqual(self.check()["reason"], "already-observed")

    def test_newer_checkpoint_advances(self):
        self.check()
        self.add_event()
        self.assertTrue(self.check(self.envelope())["checkpoint_recorded"])
        self.assertEqual(mod.read_floor(self.store, self.issuer)["sequence"], 2)

    def test_old_checkpoint_rejected_after_advance(self):
        self.check()
        self.add_event()
        self.check(self.envelope())
        # Old signed checkpoint is valid but current chain is newer: must fail closed.
        result = self.check(self.first)
        self.assertFalse(result["checkpoint_recorded"])

    def test_revoked_issuer_no_store_created(self):
        result = self.check(revoked={self.issuer})
        self.assertEqual(result["reason"], "checkpoint-issuer-revoked")
        self.assertFalse(self.store.exists())

    def test_unknown_root_no_store_created(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-checkpoint-issuer")
        self.assertFalse(self.store.exists())

    def test_signature_corrupted_no_store(self):
        altered = copy.deepcopy(self.first)
        altered["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(altered)["reason"], "invalid-checkpoint-signature")
        self.assertFalse(self.store.exists())

    def test_external_floor_blocks_stale(self):
        self.assertEqual(self.check(minimum=2)["reason"], "stale-checkpoint")
        self.assertFalse(self.store.exists())

    def test_read_missing_store_returns_none(self):
        self.assertIsNone(mod.read_floor(self.store, self.issuer))

    def test_bogus_revocation_policy_fails_closed(self):
        self.assertEqual(self.check(revoked={"wrong"})["reason"], "invalid-revocation-policy")
        self.assertFalse(self.store.exists())

    def test_checkpoint_remains_pending_not_authorized(self):
        result = self.check()
        self.assertEqual(result["state"], "pending-review")
        self.assertEqual(result["reason"], "local-checkpoint-only-not-an-external-anchor")


if __name__ == "__main__":
    unittest.main()
