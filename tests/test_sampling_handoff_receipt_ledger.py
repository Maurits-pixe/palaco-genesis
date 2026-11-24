"""Atomic sampling handoff receipt register: replay, rollback, tampering."""
import copy
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "handoff_receipt_ledger_fixture",
    ROOT/"tests"/"test_sampling_succession_evidence_handoff.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "handoff_receipt_ledger",ROOT/"tools"/"sampling_handoff_receipt_ledger.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SamplingHandoffReceiptLedgerTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.SamplingSuccessionEvidenceHandoffTests(
            methodName="test_valid_receipt_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db=Path(tmp.name)/"receipt-ledger.sqlite"
        self.trust={
            "source_db":self.f.f.f.f.db,
            "witness_roots":self.f.f.f.roots,
            "witness_organizations":self.f.f.f.orgs,
            "revoked_witnesses":set(),
            "required_organizations":2,
            "trusted_genesis":self.f.f.genesis,
            "trusted_head":self.f.f.head,
            "minimum_revision":1,
            "trusted_ledger_head":self.f.f.f.recorded["head_hash"],
            "minimum_ledger_batches":1,
            "expected_recipient":"archive-reviewer",
            "expected_package_hash":self.f.digest,
            "expected_nonce":self.f.nonce,
            "used_nonces":set(),
            "recipient_roots":self.f.roots,
            "allowed_recipients":{self.f.key_id},
            "revoked_recipients":set()
        }

    def record(self,head=mod.GENESIS,floor=0,package=None,receipt=None,trust=None):
        result=mod.register(
            self.db,self.f.package if package is None else package,
            self.f.receipt if receipt is None else receipt,
            self.trust if trust is None else trust,head,floor)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def inspect(self,head,minimum=1):
        result=mod.inspect(self.db,head,minimum)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        return result

    def test_trigger_deleting_inserted_nonce_rolls_back(self):
        with sqlite3.connect(self.db) as conn:
            mod._schema(conn)
            conn.execute("""CREATE TRIGGER suppress_nonce AFTER INSERT
                ON sampling_handoff_nonces BEGIN
                DELETE FROM sampling_handoff_nonces
                WHERE nonce_hex=NEW.nonce_hex;
                END""")
        result=self.record()
        self.assertFalse(result["recorded"])
        self.assertEqual(result["reason"],
                         "handoff-receipt-ledger-postwrite-integrity-failed")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_receipts").fetchone()[0],0)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_nonces").fetchone()[0],0)

    def test_trigger_corrupting_inserted_event_rolls_back(self):
        with sqlite3.connect(self.db) as conn:
            mod._schema(conn)
            conn.execute("""CREATE TRIGGER alter_event AFTER INSERT
                ON sampling_handoff_receipts BEGIN
                UPDATE sampling_handoff_receipts SET event_hash=printf('%064d',0)
                WHERE sequence=NEW.sequence;
                END""")
        result=self.record()
        self.assertFalse(result["recorded"])
        self.assertEqual(result["reason"],
                         "handoff-receipt-ledger-postwrite-integrity-failed")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_receipts").fetchone()[0],0)

    def test_extraneous_nonce_index_row_denied(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO sampling_handoff_nonces VALUES(?,?)",
                         ("f"*64,99999))
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_oversized_nonce_index_fails_closed(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.executemany(
                "INSERT INTO sampling_handoff_nonces VALUES(?,?)",
                ((f"{i:064x}",i+2) for i in range(mod.MAX_RECORDS+1)))
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_entry_inspection_requires_valid_independent_head(self):
        first=self.record()
        result=mod.inspect_entry(self.db,first["head_hash"],1,1)
        self.assertTrue(result["entry_valid"])
        self.assertEqual(result["state"],"pending-review")
        self.assertEqual(result["package_sha256"],self.f.digest)
        self.assertEqual(result["receipt_nonce_hex"],self.f.nonce)
        self.assertEqual(result["event_hash"],first["head_hash"])
        self.assertFalse(result["authorization_granted"])
        self.assertEqual(mod.inspect_entry(self.db,"f"*64,1,1)["reason"],
                         "handoff-receipt-ledger-head-mismatch")

    def test_entry_inspection_rejects_invalid_sequence(self):
        first=self.record()
        for index in (True,0,-1,"1",mod.MAX_RECORDS+1):
            with self.subTest(index=index):
                self.assertEqual(
                    mod.inspect_entry(self.db,first["head_hash"],1,index)["reason"],
                    "invalid-independent-handoff-entry-policy")
        self.assertEqual(
            mod.inspect_entry(self.db,first["head_hash"],1,2)["reason"],
            "handoff-receipt-entry-not-found")

    def test_entry_inspection_detects_tampering_and_rollback(self):
        first=self.record()
        self.assertEqual(
            mod.inspect_entry(self.db,first["head_hash"],2,1)["reason"],
            "handoff-receipt-ledger-rollback")
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sampling_handoff_receipts SET receipt_sha256=?",
                         ("f"*64,))
        self.assertEqual(
            mod.inspect_entry(self.db,first["head_hash"],1,1)["reason"],
            "handoff-receipt-ledger-integrity-failed")

    def test_entry_inspection_does_not_create_missing_database(self):
        self.assertEqual(mod.inspect_entry(self.db,"f"*64,1,1)["reason"],
                         "missing-handoff-receipt-ledger")
        self.assertFalse(self.db.exists())

    def test_reverified_receipt_matches_pinned_entry(self):
        first=self.record()
        result=mod.verify_entry_evidence(
            self.db,self.f.package,self.f.receipt,self.trust,
            first["head_hash"],1,1)
        self.assertTrue(result["evidence_valid"])
        self.assertEqual(result["receipt_sha256"],first["receipt_sha256"])
        self.assertEqual(result["state"],"pending-review")
        self.assertFalse(result["authorization_granted"])

    def test_reverified_evidence_rejects_invalid_signature(self):
        first=self.record()
        invalid=copy.deepcopy(self.f.receipt)
        invalid["signature_b64"]="!"
        result=mod.verify_entry_evidence(
            self.db,self.f.package,invalid,self.trust,first["head_hash"],1,1)
        self.assertFalse(result["evidence_valid"])
        self.assertEqual(result["reason"],"invalid-handoff-signature-format")

    def test_reverified_evidence_rejects_revoked_recipient(self):
        first=self.record()
        changed=dict(self.trust,revoked_recipients={self.f.key_id})
        result=mod.verify_entry_evidence(
            self.db,self.f.package,self.f.receipt,changed,
            first["head_hash"],1,1)
        self.assertFalse(result["evidence_valid"])
        self.assertEqual(result["reason"],"handoff-recipient-revoked")

    def test_reverified_evidence_requires_pinned_entry(self):
        first=self.record()
        result=mod.verify_entry_evidence(
            self.db,self.f.package,self.f.receipt,self.trust,"f"*64,1,1)
        self.assertFalse(result["evidence_valid"])
        self.assertEqual(result["reason"],"handoff-receipt-ledger-head-mismatch")
        missing=mod.verify_entry_evidence(
            self.db,self.f.package,self.f.receipt,self.trust,
            first["head_hash"],1,2)
        self.assertEqual(missing["reason"],"handoff-receipt-entry-not-found")

    def test_reverified_evidence_rejects_mutated_valid_receipt(self):
        first=self.record()
        other_nonce="e"*64
        alternate=self.f.sign({"receipt_nonce_hex":other_nonce})
        changed=dict(self.trust,expected_nonce=other_nonce)
        result=mod.verify_entry_evidence(
            self.db,self.f.package,alternate,changed,first["head_hash"],1,1)
        self.assertFalse(result["evidence_valid"])
        self.assertEqual(result["reason"],"handoff-entry-evidence-mismatch")

    def test_registered_pending_only(self):
        first=self.record()
        self.assertTrue(first["recorded"])
        self.assertEqual(first["receipts"],1)
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])

    def test_repeated_nonce_denied(self):
        first=self.record()
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-nonce-replayed")
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])

    def test_stale_prior_head_denied(self):
        self.record()
        self.assertEqual(self.record()["reason"],"handoff-receipt-ledger-head-mismatch")

    def test_independent_floor_rollback_denied(self):
        self.record()
        self.assertEqual(self.inspect("f"*64,2)["reason"],"handoff-receipt-ledger-rollback")

    def test_wrong_external_head_denied(self):
        self.record()
        self.assertEqual(self.inspect("f"*64)["reason"],"handoff-receipt-ledger-head-mismatch")

    def test_no_external_pin_denied(self):
        self.assertEqual(self.record(head=None)["reason"],"missing-independent-handoff-ledger-pin")
        self.assertFalse(self.db.exists())

    def test_boolean_floor_denied(self):
        self.assertEqual(self.record(floor=True)["reason"],"missing-independent-handoff-ledger-pin")

    def test_bad_policy_denied(self):
        trust=dict(self.trust)
        trust.pop("recipient_roots")
        self.assertEqual(self.record(trust=trust)["reason"],
                         "invalid-handoff-ledger-verification-policy")

    def test_signed_receipt_tampering_never_recorded(self):
        receipt=copy.deepcopy(self.f.receipt)
        receipt["signature_b64"]="!"
        self.assertEqual(self.record(receipt=receipt)["reason"],"invalid-handoff-signature-format")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM sampling_handoff_receipts").fetchone()[0],0)

    def test_untrusted_recipient_never_recorded(self):
        trust=dict(self.trust,recipient_roots={})
        self.assertEqual(self.record(trust=trust)["reason"],"untrusted-handoff-recipient")

    def test_revoked_recipient_never_recorded(self):
        trust=dict(self.trust,revoked_recipients={self.f.key_id})
        self.assertEqual(self.record(trust=trust)["reason"],"handoff-recipient-revoked")

    def test_revoked_witness_never_recorded(self):
        trust=dict(self.trust,revoked_witnesses={self.f.f.f.keys[1]})
        self.assertEqual(self.record(trust=trust)["reason"],
                         "insufficient-eligible-succession-organizations")

    def test_tampered_local_hash_denied(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sampling_handoff_receipts SET event_hash=?",("f"*64,))
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_deleted_nonce_denied(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM sampling_handoff_nonces")
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_tampered_receipt_digest_denied(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sampling_handoff_receipts SET receipt_sha256=?",("f"*64,))
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_tampering_blocks_next_write(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sampling_handoff_receipts SET previous_hash=?",("f"*64,))
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_readonly_inspection(self):
        first=self.record()
        before=self.db.stat().st_size
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])
        self.assertEqual(self.db.stat().st_size,before)

    def test_read_does_not_create_ledger(self):
        self.assertEqual(self.inspect("f"*64)["reason"],"missing-handoff-receipt-ledger")
        self.assertFalse(self.db.exists())

    def test_in_memory_rejected(self):
        self.db=":memory:"
        self.assertEqual(self.record()["reason"],"persistent-handoff-receipt-ledger-required")

    def test_extra_package_permission_denied(self):
        package=dict(self.f.package,authorization_granted=True)
        self.assertEqual(self.record(package=package)["reason"],"invalid-handoff-package")

    def test_replayed_external_nonce_denied(self):
        trust=dict(self.trust,used_nonces={self.f.nonce})
        self.assertEqual(self.record(trust=trust)["reason"],"handoff-receipt-nonce-replayed")

    def test_reused_key_package_pair_denied(self):
        first=self.record()
        alternate_nonce="e"*64
        second=self.f.sign({"receipt_nonce_hex":alternate_nonce})
        trust=dict(self.trust,expected_nonce=alternate_nonce)
        self.assertEqual(self.record(head=first["head_hash"],floor=1,
                                     receipt=second,trust=trust)["reason"],
                         "duplicate-handoff-package-or-nonce")
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])


if __name__=="__main__":
    unittest.main()
