"""Ed25519 receipt audit anchor: verify exact chain and externally pinned floor."""
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
spec = importlib.util.spec_from_file_location(
    "receipt_anchor", ROOT / "tools" / "signed_receipt_chain_anchor.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedReceiptChainAnchorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "receipts.sqlite"
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE observed_handoff_receipts(
                receipt_id TEXT PRIMARY KEY,bundle_sha256 TEXT,recipient_id TEXT,
                custodian_key_id TEXT,receipt_digest TEXT)""")
            mod.audit._schema(c)
        with sqlite3.connect(self.db) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO observed_handoff_receipts VALUES(?,?,?,?,?)",
                      ("1"*32, "b"*64, "custodian-a", "c"*64, "d"*64))
            self.head = mod.audit.append(c,"1"*32,"b"*64,"custodian-a","c"*64,"d"*64)["head_hash"]
            c.commit()
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(13,45)))  # TEST ONLY
        pub = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(pub).hexdigest()
        self.roots = {self.key_id:pub}

    def envelope(self, entries=1, head=None):
        body = {"schema_version":"0.1.0","entries":entries,
                "receipt_head_sha256": self.head if head is None else head}
        sig = self.private.sign(mod.DOMAIN + mod.canonical_anchor(body))
        return {"anchor":body,"witness_key_id":self.key_id,
                "signature_b64":base64.b64encode(sig).decode()}

    def check(self, env=None, roots=None, revoked=None, minimum=1):
        result = mod.verify(self.db, self.envelope() if env is None else env,
                            self.roots if roots is None else roots,
                            set() if revoked is None else revoked, minimum)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_signed_anchor_pending_only(self):
        self.assertTrue(self.check()["anchor_valid"])

    def test_unknown_issuer_fails(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-witness")

    def test_revoked_issuer_fails(self):
        self.assertEqual(self.check(revoked={self.key_id})["reason"],"witness-revoked")

    def test_bad_signature_fails(self):
        e=self.envelope()
        e["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(e)["reason"],"invalid-anchor-signature")

    def test_changed_anchor_fails(self):
        e=self.envelope()
        e["anchor"]["receipt_head_sha256"]="f"*64
        self.assertEqual(self.check(e)["reason"],"invalid-anchor-signature")

    def test_tampered_database_fails(self):
        e=self.envelope()
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE receipt_audit_chain SET receipt_digest=?", ("f"*64,))
        self.assertEqual(self.check(e)["reason"],"receipt-chain-corrupt")

    def test_tampered_index_fails(self):
        e=self.envelope()
        with sqlite3.connect(self.db) as c:
            c.execute("DELETE FROM observed_handoff_receipts")
        self.assertEqual(self.check(e)["reason"],"receipt-index-chain-mismatch")

    def test_missing_database_not_created(self):
        e=self.envelope()
        self.db.unlink()
        self.assertEqual(self.check(e)["reason"],"missing-receipt-db")
        self.assertFalse(self.db.exists())

    def test_minimum_floor_fails_stale(self):
        self.assertEqual(self.check(minimum=2)["reason"],"stale-receipt-anchor")

    def test_claimed_count_mismatch(self):
        e=self.envelope(entries=2)
        self.assertEqual(self.check(e)["reason"],"receipt-chain-count-mismatch")

    def test_extra_authority_field_denied(self):
        e=self.envelope()
        e["authorized"]=True
        self.assertEqual(self.check(e)["reason"],"invalid-envelope")

    def test_false_boolean_sequence_rejected(self):
        e=self.envelope()
        e["anchor"]["entries"]=True
        self.assertEqual(self.check(e)["reason"],"invalid-anchor-entries")

    def test_invalid_revocation_set_rejected(self):
        self.assertEqual(self.check(revoked={"abc"})["reason"],"invalid-revocation-policy")

    def test_newer_local_head_cannot_match_old_anchor(self):
        e=self.envelope()
        with sqlite3.connect(self.db) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO observed_handoff_receipts VALUES(?,?,?,?,?)",
                      ("2"*32,"b"*64,"custodian-b","c"*64,"d"*64))
            mod.audit.append(c,"2"*32,"b"*64,"custodian-b","c"*64,"d"*64)
            c.commit()
        self.assertEqual(self.check(e)["reason"],"receipt-chain-head-mismatch")


if __name__=="__main__":
    unittest.main()
