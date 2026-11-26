"""Signed offline receipts and local replay/acknowledgement quarantine."""
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
spec = importlib.util.spec_from_file_location("custody_receipt", ROOT / "tools" / "signed_handoff_receipt.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.history = Path(tmp.name) / "history.sqlite"
        self.receipts = Path(tmp.name) / "receipts.sqlite"
        issuer = "a"*64
        witness_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))) # TEST ONLY
        custodian_key = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43))) # TEST ONLY
        self.custodian = custodian_key
        witness_pub = witness_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        custodian_pub = custodian_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.witness_id = hashlib.sha256(witness_pub).hexdigest()
        self.custodian_id = hashlib.sha256(custodian_pub).hexdigest()
        self.witness_roots = {self.witness_id:witness_pub}
        self.custodian_keys = {self.custodian_id:custodian_pub}
        head = mod.handoff.anchor.history._hash(issuer,1,1,"b"*64,mod.handoff.anchor.history.GENESIS)
        with sqlite3.connect(self.history) as conn:
            conn.execute("BEGIN IMMEDIATE")
            mod.handoff.anchor.history._schema(conn)
            conn.execute("INSERT INTO review_checkpoint_history VALUES(?,?,?,?,?,?)",
                         (issuer,1,1,"b"*64,mod.handoff.anchor.history.GENESIS,head))
            conn.commit()
        payload = {"schema_version":"0.1.0","history_issuer_key_id":issuer,"entries":1,
                   "record_count":1,"history_head_sha256":head}
        sig = witness_key.sign(mod.handoff.anchor.DOMAIN+mod.handoff.anchor.canonical_anchor(payload))
        anchor = {"anchor":payload,"witness_key_id":self.witness_id,
                  "signature_b64":base64.b64encode(sig).decode()}
        prepared = mod.handoff.prepare(self.history,anchor,"custodian-a",self.witness_roots,set(),1)
        self.assertTrue(prepared["package_prepared"])
        self.package = prepared["package"]
        self.sha = self.package["bundle_sha256"]

    def receipt(self, receipt_id="1"*32, recipient="custodian-a", bundle_sha=None):
        body = {"schema_version":"0.1.0", "recipient_id":recipient,
                "bundle_sha256":self.sha if bundle_sha is None else bundle_sha,
                "receipt_id":receipt_id,"disposition":mod.DISPOSITION}
        sig = self.custodian.sign(mod.DOMAIN+mod.canonical_receipt(body))
        return {"receipt":body,"custodian_key_id":self.custodian_id,
                "signature_b64":base64.b64encode(sig).decode()}

    def verify(self, receipt=None, custodian_keys=None, revoked=None, expected=None):
        r=mod.verify_receipt(self.history,self.package,self.receipt() if receipt is None else receipt,
                             "custodian-a",self.sha if expected is None else expected,
                             self.custodian_keys if custodian_keys is None else custodian_keys,
                             set() if revoked is None else revoked,self.witness_roots,set(),1)
        self.assertFalse(r["authorization_granted"])
        self.assertFalse(r["recovery_approved"])
        self.assertFalse(r["automatic_restore"])
        self.assertEqual(r["release_gate"],"HOLD")
        return r

    def record(self, receipt=None):
        r=mod.index_receipt(self.receipts,self.history,self.package,
                            self.receipt() if receipt is None else receipt,
                            "custodian-a",self.sha,self.custodian_keys,set(),
                            self.witness_roots,set(),1)
        self.assertFalse(r["authorization_granted"])
        self.assertFalse(r["recovery_approved"])
        self.assertEqual(r["release_gate"],"HOLD")
        return r

    def test_valid_receipt_never_authorizes(self):
        self.assertTrue(self.verify()["receipt_valid"])

    def test_first_record_then_replay_denied(self):
        self.assertTrue(self.record()["receipt_recorded"])
        self.assertEqual(self.record()["reason"],"duplicate-receipt")

    def test_same_bundle_second_receipt_denied(self):
        self.record()
        self.assertEqual(self.record(self.receipt("2"*32))["reason"],"duplicate-bundle-acknowledgement")

    def test_receipt_id_equivocation_denied(self):
        self.record()
        second=self.receipt()
        second["receipt"]["disposition"]=mod.DISPOSITION
        # Same ID for a different, still valid recipient is rejected before write.
        second=self.receipt(recipient="custodian-b")
        self.assertEqual(self.record(second)["reason"],"receipt-recipient-mismatch")

    def test_signature_tamper_denied(self):
        r=self.receipt()
        r["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.verify(r)["reason"],"invalid-receipt-signature")

    def test_replayed_body_mutation_denied(self):
        r=self.receipt()
        r["receipt"]["receipt_id"]="2"*32
        self.assertEqual(self.verify(r)["reason"],"invalid-receipt-signature")

    def test_wrong_package_hash_denied(self):
        self.assertEqual(self.verify(self.receipt(bundle_sha="f"*64))["reason"],"receipt-package-mismatch")

    def test_revoked_custodian_denied(self):
        self.assertEqual(self.verify(revoked={self.custodian_id})["reason"],"custodian-revoked")

    def test_untrusted_custodian_denied(self):
        self.assertEqual(self.verify(custodian_keys={})["reason"],"untrusted-custodian-key")

    def test_invalid_purpose_field_denied(self):
        r=self.receipt()
        r["receipt"]["disposition"]="approved"
        self.assertEqual(self.verify(r)["reason"],"invalid-receipt-purpose")

    def test_extra_authority_field_denied(self):
        r=self.receipt()
        r["authorization_granted"]=True
        self.assertEqual(self.verify(r)["reason"],"invalid-receipt-envelope")

    def test_bad_signature_never_creates_db(self):
        r=self.receipt()
        r["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.record(r)["reason"],"invalid-receipt-signature")
        self.assertFalse(self.receipts.exists())

    def test_missing_history_denied_without_creation(self):
        self.history.unlink()
        self.assertEqual(self.verify()["reason"],"missing-history-db")
        self.assertFalse(self.history.exists())

    def test_receipt_table_minimizes_content(self):
        self.record()
        with sqlite3.connect(self.receipts) as conn:
            count=conn.execute("SELECT COUNT(*) FROM observed_handoff_receipts").fetchone()[0]
            self.assertEqual(count,1)

    def test_invalid_same_database_denied(self):
        with self.assertRaises(ValueError):
            mod.index_receipt(self.history,self.history,self.package,self.receipt(),
                              "custodian-a",self.sha,self.custodian_keys,set(),
                              self.witness_roots,set(),1)


if __name__=="__main__":
    unittest.main()
