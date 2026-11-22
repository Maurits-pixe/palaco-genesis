"""Adversarial tests for detached custody acknowledgement chain witness."""
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
_spec = importlib.util.spec_from_file_location(
    "signed_ack_head", ROOT / "tools" / "signed_custody_ack_anchor.py")
signed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(signed)


class SignedCustodyAckAnchorTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db = Path(t.name) / "ack.sqlite"
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(31, 63)))  # TEST ONLY
        public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(public).hexdigest()
        self.roots = {self.key_id: public}
        with sqlite3.connect(self.db) as conn:
            conn.execute("""CREATE TABLE custody_anchor_acknowledgements(
                receipt_id TEXT PRIMARY KEY, custodian_key_id TEXT,
                recipient_id TEXT, package_sha256 TEXT, receipt_sha256 TEXT)""")
            signed.chain.schema(conn)
        self.head = self.add_event("1" * 32, "c" * 64)

    def add_event(self, receipt, package):
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO custody_anchor_acknowledgements VALUES(?,?,?,?,?)",
                         (receipt, "b"*64, "custodian-a", package, "d"*64))
            index, chain = signed.chain._read(conn)
            # append() expects the matching acknowledgement and previous
            # audit rows to have identical lengths before insert. Insert the
            # audit event explicitly for a faithful committed fixture.
            seq = len(chain) + 1
            previous = chain[-1][-1] if chain else signed.chain.GENESIS
            head = signed.chain._hash(seq, receipt, "b"*64, "custodian-a",
                                      package, "d"*64, previous)
            conn.execute("INSERT INTO custody_ack_audit_chain VALUES(?,?,?,?,?,?,?,?)",
                         (seq, receipt, "b"*64, "custodian-a", package, "d"*64, previous, head))
            conn.commit()
            return head

    def envelope(self, entries=1, head=None):
        body = {"schema_version": "0.1.0", "entries": entries,
                "ack_head_sha256": self.head if head is None else head}
        signature = self.key.sign(signed.DOMAIN + signed.canonical_anchor(body))
        return {"anchor": body, "witness_key_id": self.key_id,
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, envelope=None, roots=None, revoked=None, minimum=1):
        result = signed.verify(self.db, self.envelope() if envelope is None else envelope,
                               self.roots if roots is None else roots,
                               set() if revoked is None else revoked, minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_signed_anchor_pending_only(self):
        self.assertTrue(self.check()["anchor_valid"])

    def test_untrusted_witness(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-ack-witness")

    def test_revoked_witness(self):
        self.assertEqual(self.check(revoked={self.key_id})["reason"], "ack-witness-revoked")

    def test_invalid_signature(self):
        e = self.envelope()
        e["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(e)["reason"], "invalid-signed-ack-signature")

    def test_invalid_signature_format(self):
        e = self.envelope()
        e["signature_b64"] = "not-base64!"
        self.assertEqual(self.check(e)["reason"], "invalid-ack-anchor-signature-format")

    def test_changed_signed_head(self):
        e = self.envelope()
        e["anchor"]["ack_head_sha256"] = "f"*64
        self.assertEqual(self.check(e)["reason"], "invalid-signed-ack-signature")

    def test_missing_external_floor(self):
        self.assertEqual(self.check(minimum=None)["reason"], "missing-external-ack-floor")

    def test_rollback_floor(self):
        self.assertEqual(self.check(minimum=2)["reason"], "stale-signed-ack-anchor")

    def test_malformed_revocation(self):
        self.assertEqual(self.check(revoked={"not-a-key"})["reason"], "invalid-witness-revocations")

    def test_added_authority_field(self):
        e = self.envelope()
        e["authorization_granted"] = True
        self.assertEqual(self.check(e)["reason"], "invalid-signed-ack-envelope")

    def test_boolean_count(self):
        e = self.envelope()
        e["anchor"]["entries"] = True
        self.assertEqual(self.check(e)["reason"], "invalid-signed-ack-count")

    def test_invalid_count_even_if_signed(self):
        e = self.envelope(entries=2)
        self.assertEqual(self.check(e)["reason"], "signed-ack-count-mismatch")

    def test_corrupt_local_event(self):
        e = self.envelope()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE custody_ack_audit_chain SET receipt_sha256=?", ("f"*64,))
        self.assertEqual(self.check(e)["reason"], "ack-chain-integrity-failed")

    def test_corrupt_index(self):
        e = self.envelope()
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM custody_anchor_acknowledgements")
        self.assertEqual(self.check(e)["reason"], "ack-chain-integrity-failed")

    def test_missing_database_does_not_get_recreated(self):
        e = self.envelope()
        self.db.unlink()
        self.assertEqual(self.check(e)["reason"], "missing-ack-register")
        self.assertFalse(self.db.exists())

    def test_older_anchor_rejected_on_newer_chain(self):
        old = self.envelope()
        self.add_event("2"*32, "e"*64)
        self.assertEqual(self.check(old)["reason"], "ack-chain-head-mismatch")


if __name__ == "__main__":
    unittest.main()
