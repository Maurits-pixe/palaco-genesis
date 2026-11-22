"""Signed custody-ledger checkpoint against rollback and signature tampering."""
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
module_spec = importlib.util.spec_from_file_location(
    "custody_ledger_anchor", ROOT / "tools" / "signed_custody_ledger_anchor.py")
anchor = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(anchor)


class CustodyLedgerAnchorTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db = Path(t.name) / "ledger.sqlite"
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(31,63)))  # TEST ONLY
        pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(pub).hexdigest()
        self.roots = {self.key_id: pub}
        self.add_record("1" * 32, "a" * 64, 1)

    def add_record(self, ident, anchor_hash, count):
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            anchor.ledger._schema(conn)
            index, events = anchor.ledger._rows(conn)
            state = anchor.ledger._validate(index, events)
            seq, prev = state["entries"] + 1, state["head_hash"]
            fields = (ident, "custodian-a", "c"*64, "d"*64,
                      "e"*64, anchor_hash, count, "f"*64)
            event = anchor.ledger._hash(seq, *fields, prev)
            conn.execute("INSERT INTO observed_custody_statements VALUES(?,?,?,?,?,?,?,?)", fields)
            conn.execute("INSERT INTO custody_statement_chain VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                         (seq, *fields, prev, event))
            conn.commit()
            return event

    def state(self):
        with sqlite3.connect(self.db) as conn:
            return anchor.ledger._validate(*anchor.ledger._rows(conn))

    def envelope(self, entries=None, head=None):
        state = self.state()
        body = {"schema_version": "0.1.0",
                "entries": state["entries"] if entries is None else entries,
                "custody_head_sha256": state["head_hash"] if head is None else head}
        signature = self.key.sign(anchor.DOMAIN + anchor.canonical_anchor(body))
        return {"anchor": body, "witness_key_id": self.key_id,
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, envelope=None, roots=None, revoked=None, minimum=1):
        result = anchor.verify(self.db, self.envelope() if envelope is None else envelope,
                               self.roots if roots is None else roots,
                               set() if revoked is None else revoked, minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_signed_chain_pending_only(self):
        self.assertTrue(self.check()["anchor_valid"])

    def test_untrusted_witness_denied(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-custody-witness")

    def test_revoked_witness_denied(self):
        self.assertEqual(self.check(revoked={self.key_id})["reason"], "custody-witness-revoked")

    def test_invalid_signature_denied(self):
        e = self.envelope()
        e["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(e)["reason"], "invalid-custody-anchor-signature")

    def test_modified_signed_head_denied(self):
        e = self.envelope()
        e["anchor"]["custody_head_sha256"] = "f"*64
        self.assertEqual(self.check(e)["reason"], "invalid-custody-anchor-signature")

    def test_invalid_signature_encoding_denied(self):
        e = self.envelope()
        e["signature_b64"] = "!"
        self.assertEqual(self.check(e)["reason"], "invalid-anchor-signature-format")

    def test_false_boolean_count_denied(self):
        e = self.envelope()
        e["anchor"]["entries"] = True
        self.assertEqual(self.check(e)["reason"], "invalid-custody-anchor-count")

    def test_extra_approval_field_denied(self):
        e = self.envelope()
        e["grant"] = True
        self.assertEqual(self.check(e)["reason"], "invalid-custody-anchor-envelope")

    def test_external_minimum_denies_stale_anchor(self):
        self.assertEqual(self.check(minimum=2)["reason"], "stale-custody-anchor")

    def test_signature_valid_but_count_mismatch_denied(self):
        self.assertEqual(self.check(self.envelope(entries=2))["reason"], "custody-anchor-count-mismatch")

    def test_mutated_index_denied(self):
        e = self.envelope()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE observed_custody_statements SET policy_sha256=?", ("9"*64,))
        self.assertEqual(self.check(e)["reason"], "custody-ledger-integrity-failed")

    def test_mutated_chain_denied(self):
        e = self.envelope()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE custody_statement_chain SET event_hash=?", ("9"*64,))
        self.assertEqual(self.check(e)["reason"], "custody-ledger-integrity-failed")

    def test_deleted_local_database_denied(self):
        e = self.envelope()
        self.db.unlink()
        self.assertEqual(self.check(e)["reason"], "missing-custody-ledger")
        self.assertFalse(self.db.exists())

    def test_newer_local_chain_does_not_match_old_checkpoint(self):
        old = self.envelope()
        self.add_record("2"*32, "b"*64, 2)
        self.assertEqual(self.check(old)["reason"], "custody-ledger-head-mismatch")

    def test_missing_floor_denied(self):
        self.assertEqual(self.check(minimum=None)["reason"], "missing-external-custody-floor")

    def test_invalid_revocation_ids_denied(self):
        self.assertEqual(self.check(revoked={"bad"})["reason"], "invalid-revocation-policy")


if __name__ == "__main__":
    unittest.main()
