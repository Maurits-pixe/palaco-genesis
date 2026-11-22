"""Offline signed-witness handoff; no implicit authority or publication."""
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
    "handoff", ROOT / "tools" / "offline_review_anchor_handoff.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class OfflineHandoffTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "history.sqlite"
        self.issuer = "a" * 64
        signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))  # TEST ONLY
        pub = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(pub).hexdigest()
        self.roots = {self.key_id: pub}
        head = mod.anchor.history._hash(
            self.issuer, 1, 1, "b"*64, mod.anchor.history.GENESIS)
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            mod.anchor.history._schema(conn)
            conn.execute("INSERT INTO review_checkpoint_history VALUES(?,?,?,?,?,?)",
                         (self.issuer, 1, 1, "b"*64, mod.anchor.history.GENESIS, head))
            conn.commit()
        body = {"schema_version": "0.1.0", "history_issuer_key_id": self.issuer,
                "entries": 1, "record_count": 1, "history_head_sha256": head}
        signature = signer.sign(mod.anchor.DOMAIN + mod.anchor.canonical_anchor(body))
        self.witness = {"anchor": body, "witness_key_id": self.key_id,
                        "signature_b64": base64.b64encode(signature).decode()}

    def pack(self, witness=None, recipient="custodian-a", roots=None, minimum=1):
        return mod.prepare(self.db, self.witness if witness is None else witness,
                           recipient, self.roots if roots is None else roots, set(), minimum)

    def verify(self, pkg, recipient="custodian-a", expected=None, roots=None,
               revoked=None, minimum=1):
        sha = pkg["bundle_sha256"] if expected is None else expected
        result = mod.verify_package(
            self.db, pkg, recipient, self.roots if roots is None else roots,
            set() if revoked is None else revoked, minimum, sha)
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_prepare_verify_only_pending(self):
        prepared = self.pack()
        self.assertTrue(prepared["package_prepared"])
        self.assertEqual(self.verify(prepared["package"])["state"], "pending-review")

    def test_deterministic_bundle_digest(self):
        self.assertEqual(self.pack()["package"]["bundle_sha256"],
                         self.pack()["package"]["bundle_sha256"])

    def test_recipient_mismatch_denied(self):
        self.assertEqual(self.verify(self.pack()["package"], recipient="other")["reason"],
                         "recipient-mismatch")

    def test_modified_anchor_denied(self):
        pkg = copy.deepcopy(self.pack()["package"])
        pkg["bundle"]["signed_anchor"]["anchor"]["record_count"] = 2
        self.assertEqual(self.verify(pkg)["reason"], "invalid-bundle")

    def test_modified_signed_payload_with_recomputed_checksums_denied(self):
        pkg = copy.deepcopy(self.pack()["package"])
        witness = pkg["bundle"]["signed_anchor"]
        witness["anchor"]["history_head_sha256"] = "f"*64
        pkg["bundle"]["anchor_sha256"] = mod._digest(b"PALACO-DETACHED-ANCHOR-ENVELOPE-V1\x00", witness)
        pkg["bundle_sha256"] = mod._digest(mod.DOMAIN, pkg["bundle"])
        self.assertEqual(self.verify(pkg)["reason"], "invalid-anchor-signature")

    def test_wrong_externally_pinned_digest_denied(self):
        self.assertEqual(self.verify(self.pack()["package"], expected="f"*64)["reason"],
                         "bundle-digest-mismatch")

    def test_revoked_witness_denied(self):
        self.assertEqual(self.verify(self.pack()["package"], revoked={self.key_id})["reason"],
                         "witness-key-revoked")

    def test_untrusted_witness_denied(self):
        self.assertEqual(self.verify(self.pack()["package"], roots={})["reason"],
                         "untrusted-witness")

    def test_freshness_floor_denied(self):
        self.assertEqual(self.verify(self.pack()["package"], minimum=2)["reason"], "stale-anchor")

    def test_no_trusted_digest_denied(self):
        self.assertEqual(self.verify(self.pack()["package"], expected="oops")["reason"],
                         "missing-external-package-digest")

    def test_missing_database_no_creation(self):
        pkg = self.pack()["package"]
        self.db.unlink()
        self.assertEqual(self.verify(pkg)["reason"], "missing-history-db")
        self.assertFalse(self.db.exists())

    def test_invalid_recipient_refuses_to_prepare(self):
        result = self.pack(recipient="../evil")
        self.assertFalse(result["package_prepared"])
        self.assertEqual(result["reason"], "invalid-recipient-id")

    def test_invalid_signature_refuses_to_prepare(self):
        witness = copy.deepcopy(self.witness)
        witness["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.pack(witness=witness)["reason"], "invalid-anchor-signature")

    def test_prepared_package_input_independent(self):
        pkg = self.pack()["package"]
        self.witness["anchor"]["record_count"] = 999
        self.assertEqual(pkg["bundle"]["signed_anchor"]["anchor"]["record_count"], 1)


if __name__ == "__main__":
    unittest.main()
