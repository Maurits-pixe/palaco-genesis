"""Atomic sampling handoff receipt register: replay, rollback, tampering."""
import copy
import importlib.util
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_nonce_integrity_failure_rolls_back_prior_receipt_insert(self):
        # BEFORE INSERT failure on the second table previously returned
        # normally from sqlite3's context manager and committed row one.
        with sqlite3.connect(self.db) as conn:
            mod._schema(conn)
            conn.execute("""CREATE TRIGGER abort_nonce BEFORE INSERT
                ON sampling_handoff_nonces BEGIN
                SELECT RAISE(ABORT, 'injected nonce insert rejection');
                END""")
        result=self.record()
        self.assertFalse(result["recorded"])
        self.assertEqual(result["reason"],"duplicate-handoff-package-or-nonce")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_receipts").fetchone()[0],0)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_nonces").fetchone()[0],0)
        # The failed attempt must not change the externally anchored genesis.
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(mod._scan(conn)["head_hash"],mod.GENESIS)

    def test_foreign_key_enforced_on_receipt_writer(self):
        # A trigger injects an orphan link into the nonce index. SQLite
        # must reject it at INSERT time, not just on a later chain scan.
        with sqlite3.connect(self.db) as conn:
            mod._schema(conn)
            conn.execute("""CREATE TRIGGER inject_orphan AFTER INSERT
                ON sampling_handoff_nonces BEGIN
                INSERT INTO sampling_handoff_nonces(nonce_hex,receipt_sequence)
                VALUES ('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                        99999);
                END""")
        result=self.record()
        self.assertFalse(result["recorded"])
        self.assertEqual(result["reason"],"duplicate-handoff-package-or-nonce")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_receipts").fetchone()[0],0)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_nonces").fetchone()[0],0)
            self.assertEqual(mod._scan(conn)["head_hash"],mod.GENESIS)

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

    def test_rejects_preexisting_schema_without_unique_package_binding(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("""CREATE TABLE sampling_handoff_receipts(
                sequence INTEGER PRIMARY KEY CHECK(sequence>0),
                recipient_id TEXT NOT NULL,
                recipient_key_id TEXT NOT NULL,
                package_sha256 TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL)""")
            conn.execute("""CREATE TABLE sampling_handoff_nonces(
                nonce_hex TEXT PRIMARY KEY,
                receipt_sequence INTEGER NOT NULL UNIQUE,
                FOREIGN KEY(receipt_sequence) REFERENCES sampling_handoff_receipts(sequence))""")
        result=self.record()
        self.assertFalse(result["recorded"])
        self.assertEqual(result["reason"],"handoff-receipt-ledger-integrity-failed")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM sampling_handoff_receipts").fetchone()[0],0)

    def test_added_receipt_column_invalidates_pinned_inspection(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("ALTER TABLE sampling_handoff_receipts ADD COLUMN injected TEXT")
        result=self.inspect(first["head_hash"])
        self.assertFalse(result["ledger_valid"])
        self.assertEqual(result["reason"],"handoff-receipt-ledger-integrity-failed")
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_evidence_verification_rechecks_concurrent_ledger_tampering(self):
        first=self.record()
        original=mod.handoff.verify_receipt

        def tamper_after_signature(*args,**kwargs):
            checked=original(*args,**kwargs)
            self.assertTrue(checked["receipt_valid"])
            with sqlite3.connect(self.db) as conn:
                conn.execute("UPDATE sampling_handoff_receipts "
                             "SET event_hash=? WHERE sequence=1",("f"*64,))
            return checked

        with patch.object(mod.handoff,"verify_receipt",
                          side_effect=tamper_after_signature):
            result=mod.verify_entry_evidence(
                self.db,self.f.package,self.f.receipt,self.trust,
                first["head_hash"],1,1)
        self.assertFalse(result["evidence_valid"])
        self.assertEqual(result["reason"],
                         "handoff-entry-changed-during-verification")
        self.assertFalse(result["authorization_granted"])

    def test_evidence_verification_rechecks_concurrent_nonce_deletion(self):
        first=self.record()
        original=mod.handoff.verify_receipt

        def delete_nonce_after_signature(*args,**kwargs):
            checked=original(*args,**kwargs)
            self.assertTrue(checked["receipt_valid"])
            with sqlite3.connect(self.db) as conn:
                conn.execute("DELETE FROM sampling_handoff_nonces "
                             "WHERE receipt_sequence=1")
            return checked

        with patch.object(mod.handoff,"verify_receipt",
                          side_effect=delete_nonce_after_signature):
            result=mod.verify_entry_evidence(
                self.db,self.f.package,self.f.receipt,self.trust,
                first["head_hash"],1,1)
        self.assertFalse(result["evidence_valid"])
        self.assertEqual(result["reason"],
                         "handoff-entry-changed-during-verification")

    def test_sqlite_storage_checks_pass_for_valid_receipt(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            self.assertTrue(mod._storage_integrity_ok(conn))
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])

    def test_sqlite_foreign_key_orphan_rejected(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            # SQLite enforcement is disabled for this tampering connection.
            conn.execute("UPDATE sampling_handoff_nonces SET "
                         "receipt_sequence=99999")
            self.assertFalse(mod._storage_integrity_ok(conn))
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_storage_integrity_failure_fails_closed(self):
        first=self.record()
        with patch.object(mod,"_storage_integrity_ok",return_value=False):
            self.assertEqual(self.inspect(first["head_hash"])["reason"],
                             "handoff-receipt-ledger-integrity-failed")
            self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                             "handoff-receipt-ledger-integrity-failed")
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])

    def test_storage_integrity_checks_unique_indexes_not_only_quick_check(self):
        first=self.record()
        statements=[]
        with sqlite3.connect(self.db) as conn:
            conn.set_trace_callback(statements.append)
            self.assertTrue(mod._storage_integrity_ok(conn))
        self.assertIn("PRAGMA integrity_check(1)",statements)
        self.assertIn("PRAGMA foreign_key_check",statements)
        self.assertNotIn("PRAGMA quick_check(1)",statements)
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])

    def test_sqlite_check_constraint_violation_denied(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("PRAGMA ignore_check_constraints=ON")
            conn.execute("UPDATE sampling_handoff_receipts SET sequence=0")
            conn.execute("PRAGMA ignore_check_constraints=OFF")
            self.assertNotEqual(conn.execute(
                "PRAGMA integrity_check(1)").fetchone(),("ok",))
        self.assertEqual(self.inspect(first["head_hash"])["reason"],
                         "handoff-receipt-ledger-integrity-failed")
        self.assertEqual(self.record(head=first["head_hash"],floor=1)["reason"],
                         "handoff-receipt-ledger-integrity-failed")

    def test_export_manifest_matches_pinned_head_and_is_read_only(self):
        first=self.record()
        before=self.db.stat().st_size
        result=mod.export_review_manifest(self.db,first["head_hash"],1)
        self.assertTrue(result["manifest_exported"])
        self.assertEqual(result["manifest"]["receipt_count"],1)
        self.assertEqual(result["manifest"]["head_hash"],first["head_hash"])
        self.assertEqual(result["manifest"]["entries"][0]["receipt_sha256"],
                         first["receipt_sha256"])
        self.assertEqual(len(result["manifest_sha256"]),64)
        self.assertEqual(self.db.stat().st_size,before)
        self.assertFalse(result["authorization_granted"])
        self.assertEqual(result["release_gate"],"HOLD")

    def test_export_manifest_rejects_wrong_pin_or_rollback(self):
        first=self.record()
        self.assertEqual(mod.export_review_manifest(
            self.db,"f"*64,1)["reason"],"handoff-receipt-ledger-head-mismatch")
        self.assertEqual(mod.export_review_manifest(
            self.db,first["head_hash"],2)["reason"],"handoff-receipt-ledger-rollback")

    def test_export_manifest_rejects_tampered_receipt(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE sampling_handoff_receipts SET "
                         "receipt_sha256=? WHERE sequence=1",("f"*64,))
        result=mod.export_review_manifest(self.db,first["head_hash"],1)
        self.assertFalse(result["manifest_exported"])
        self.assertEqual(result["reason"],"handoff-receipt-ledger-integrity-failed")

    def test_export_manifest_rejects_untrusted_or_missing_store(self):
        self.assertEqual(mod.export_review_manifest(
            self.db,"f"*64,1)["reason"],"missing-handoff-receipt-ledger")
        self.assertFalse(self.db.exists())
        self.assertEqual(mod.export_review_manifest(
            self.db,mod.GENESIS,0)["reason"],
            "missing-independent-handoff-ledger-pin")

    def test_offline_manifest_verifies_without_database(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        self.db.unlink()
        result=mod.verify_review_manifest(
            exported["manifest"],exported["manifest_sha256"],
            recorded["head_hash"],1)
        self.assertTrue(result["manifest_valid"])
        self.assertEqual(result["state"],"pending-review")
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_offline_manifest_rejects_tampered_entry(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        manifest=copy.deepcopy(exported["manifest"])
        manifest["entries"][0]["receipt_sha256"]="f"*64
        result=mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],recorded["head_hash"],1)
        self.assertFalse(result["manifest_valid"])
        self.assertEqual(result["reason"],"review-manifest-chain-invalid")

    def test_offline_manifest_rejects_invalid_independent_pins(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        manifest=exported["manifest"]
        self.assertEqual(mod.verify_review_manifest(
            manifest,"f"*64,recorded["head_hash"],1)["reason"],
            "review-manifest-digest-mismatch")
        self.assertEqual(mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],"f"*64,1)["reason"],
            "review-manifest-head-mismatch")
        self.assertEqual(mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],recorded["head_hash"],2)["reason"],
            "review-manifest-rollback")
        self.assertEqual(mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],recorded["head_hash"],True)["reason"],
            "missing-independent-manifest-pins")

    def test_offline_manifest_rejects_duplicate_nonce_and_bad_sequence(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        manifest=copy.deepcopy(exported["manifest"])
        manifest["entries"].append(copy.deepcopy(manifest["entries"][0]))
        manifest["entries"][1]["sequence"]=2
        manifest["entries"][1]["previous_hash"]=recorded["head_hash"]
        manifest["receipt_count"]=2
        self.assertEqual(mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],recorded["head_hash"],1)["reason"],
            "review-manifest-chain-invalid")
        manifest["entries"][1]["sequence"]=True
        self.assertEqual(mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],recorded["head_hash"],1)["reason"],
            "invalid-review-manifest-entry")

    def test_offline_manifest_rejects_extra_fields(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        manifest=copy.deepcopy(exported["manifest"])
        manifest["authorization_granted"]=True
        self.assertEqual(mod.verify_review_manifest(
            manifest,exported["manifest_sha256"],recorded["head_hash"],1)["reason"],
            "invalid-review-manifest-schema")

    def _independently_pinned_manifest(self,manifest):
        body=json.dumps(manifest,sort_keys=True,separators=(",",":"),
                        ensure_ascii=False,allow_nan=False).encode("utf-8")
        return hashlib.sha256(mod.MANIFEST_DOMAIN+body).hexdigest()

    def test_offline_manifest_succession_identical_pins(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        result=mod.verify_manifest_succession(
            exported["manifest"],exported["manifest_sha256"],recorded["head_hash"],
            exported["manifest"],exported["manifest_sha256"],recorded["head_hash"],1)
        self.assertTrue(result["succession_valid"])
        self.assertEqual(result["current_receipts"],1)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_offline_manifest_succession_accepts_valid_append_only_history(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        current=copy.deepcopy(exported["manifest"])
        prev=current["entries"][0]
        nonce="e"*64
        package="f"*64
        event=mod._digest(2,prev["recipient_id"],prev["recipient_key_id"],
                          package,nonce,prev["receipt_sha256"],recorded["head_hash"])
        next_entry=dict(prev,sequence=2,package_sha256=package,
                        receipt_nonce_hex=nonce,previous_hash=recorded["head_hash"],
                        event_hash=event)
        current["entries"].append(next_entry)
        current["receipt_count"]=2
        current["head_hash"]=event
        digest=self._independently_pinned_manifest(current)
        result=mod.verify_manifest_succession(
            exported["manifest"],exported["manifest_sha256"],recorded["head_hash"],
            current,digest,event,1)
        self.assertTrue(result["succession_valid"])
        self.assertEqual(result["previous_receipts"],1)
        self.assertEqual(result["current_receipts"],2)
        self.assertFalse(result["authorization_granted"])

    def test_offline_manifest_succession_rejects_rewritten_history(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        rewritten=copy.deepcopy(exported["manifest"])
        entry=rewritten["entries"][0]
        entry["recipient_id"]="different-reviewer"
        alternate=mod._digest(1,entry["recipient_id"],entry["recipient_key_id"],
                              entry["package_sha256"],entry["receipt_nonce_hex"],
                              entry["receipt_sha256"],mod.GENESIS)
        entry["event_hash"]=alternate
        rewritten["head_hash"]=alternate
        result=mod.verify_manifest_succession(
            exported["manifest"],exported["manifest_sha256"],recorded["head_hash"],
            rewritten,self._independently_pinned_manifest(rewritten),alternate,1)
        self.assertFalse(result["succession_valid"])
        self.assertEqual(result["reason"],"review-manifest-history-rewritten")

    def test_offline_manifest_succession_rejects_rollback_and_bad_pins(self):
        recorded=self.record()
        exported=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        manifest=exported["manifest"]
        self.assertEqual(mod.verify_manifest_succession(
            manifest,exported["manifest_sha256"],recorded["head_hash"],
            manifest,"f"*64,recorded["head_hash"],1)["reason"],
            "current-review-manifest-digest-mismatch")
        self.assertEqual(mod.verify_manifest_succession(
            manifest,"f"*64,recorded["head_hash"],
            manifest,exported["manifest_sha256"],recorded["head_hash"],1)["reason"],
            "previous-review-manifest-digest-mismatch")
        self.assertEqual(mod.verify_manifest_succession(
            manifest,exported["manifest_sha256"],recorded["head_hash"],
            manifest,exported["manifest_sha256"],recorded["head_hash"],2)["reason"],
            "previous-review-manifest-rollback")

    def _delta_fixture(self):
        recorded=self.record()
        original=mod.export_review_manifest(self.db,recorded["head_hash"],1)
        previous=original["manifest"]
        current=copy.deepcopy(previous)
        first=current["entries"][0]
        nonce="e"*64
        package="f"*64
        digest=mod._digest(2,first["recipient_id"],first["recipient_key_id"],
                           package,nonce,first["receipt_sha256"],
                           recorded["head_hash"])
        current["entries"].append(dict(first,sequence=2,
            package_sha256=package,receipt_nonce_hex=nonce,
            previous_hash=recorded["head_hash"],event_hash=digest))
        current["receipt_count"]=2
        current["head_hash"]=digest
        next_sha=self._independently_pinned_manifest(current)
        created=mod.create_review_delta(
            previous,original["manifest_sha256"],recorded["head_hash"],
            current,next_sha,digest,1)
        self.assertTrue(created["delta_created"])
        return previous,original["manifest_sha256"],recorded["head_hash"],created,digest

    def test_offline_delta_accepts_valid_append_without_database(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        self.db.unlink()
        result=mod.verify_review_delta(
            previous,sha,head,created["delta"],created["delta_sha256"],
            current_head,1)
        self.assertTrue(result["delta_valid"])
        self.assertEqual(result["previous_receipts"],1)
        self.assertEqual(result["current_receipts"],2)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_offline_delta_rejects_changed_record_with_original_pin(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        changed=copy.deepcopy(created["delta"])
        changed["entries"][0]["receipt_sha256"]="f"*64
        result=mod.verify_review_delta(
            previous,sha,head,changed,created["delta_sha256"],
            current_head,1)
        self.assertFalse(result["delta_valid"])
        self.assertEqual(result["reason"],"review-delta-digest-mismatch")

    def test_offline_delta_rejects_rehashed_but_broken_chain(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        changed=copy.deepcopy(created["delta"])
        changed["entries"][0]["previous_hash"]=mod.GENESIS
        result=mod.verify_review_delta(
            previous,sha,head,changed,mod._delta_hash(changed),current_head,1)
        self.assertFalse(result["delta_valid"])
        self.assertEqual(result["reason"],"current-review-manifest-chain-invalid")

    def test_offline_delta_rejects_mismatched_counts_and_pins(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        altered=copy.deepcopy(created["delta"])
        altered["previous_receipts"]=0
        self.assertEqual(mod.verify_review_delta(
            previous,sha,head,altered,mod._delta_hash(altered),
            current_head,1)["reason"],"invalid-review-delta-schema-or-pins")
        self.assertEqual(mod.verify_review_delta(
            previous,sha,head,created["delta"],"f"*64,
            current_head,1)["reason"],"review-delta-digest-mismatch")
        self.assertEqual(mod.verify_review_delta(
            previous,sha,head,created["delta"],created["delta_sha256"],
            "f"*64,1)["reason"],"invalid-review-delta-schema-or-pins")

    def test_offline_delta_rejects_unexpected_authority_field(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        altered=copy.deepcopy(created["delta"])
        altered["authorization_granted"]=True
        self.assertEqual(mod.verify_review_delta(
            previous,sha,head,altered,created["delta_sha256"],
            current_head,1)["reason"],"invalid-review-delta-schema")

    def test_strict_delta_requires_independent_current_manifest_pin(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        delta=created["delta"]
        reconstructed={"schema_version":"0.1.0",
                       "receipt_count":delta["current_receipts"],
                       "head_hash":current_head,
                       "entries":previous["entries"]+delta["entries"]}
        independent_sha=self._independently_pinned_manifest(reconstructed)
        self.db.unlink()
        result=mod.verify_review_delta_with_manifest_pin(
            previous,sha,head,delta,created["delta_sha256"],
            current_head,independent_sha,1)
        self.assertTrue(result["delta_valid"])
        self.assertEqual(result["current_manifest_sha256"],independent_sha)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_strict_delta_rejects_wrong_or_missing_manifest_pin(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        for pin,expected in (("f"*64,"current-review-manifest-pin-mismatch"),
                             (None,"missing-independent-current-manifest-pin"),
                             (True,"missing-independent-current-manifest-pin")):
            with self.subTest(pin=pin):
                result=mod.verify_review_delta_with_manifest_pin(
                    previous,sha,head,created["delta"],created["delta_sha256"],
                    current_head,pin,1)
                self.assertFalse(result["delta_valid"])
                self.assertEqual(result["reason"],expected)

    def test_strict_delta_preserves_underlying_chain_failure(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        changed=copy.deepcopy(created["delta"])
        changed["entries"][0]["previous_hash"]=mod.GENESIS
        result=mod.verify_review_delta_with_manifest_pin(
            previous,sha,head,changed,mod._delta_hash(changed),
            current_head,"a"*64,1)
        self.assertFalse(result["delta_valid"])
        self.assertEqual(result["reason"],"current-review-manifest-chain-invalid")

    def _fork_pins(self,previous,delta):
        full={"schema_version":"0.1.0","receipt_count":delta["current_receipts"],
              "head_hash":delta["current_head"],
              "entries":previous["entries"]+delta["entries"]}
        return mod._delta_hash(delta),self._independently_pinned_manifest(full)

    def test_offline_fork_assessment_detects_distinct_valid_successors(self):
        previous,sha,head,created,left_head=self._delta_fixture()
        left=created["delta"]
        left_delta_pin,left_manifest_pin=self._fork_pins(previous,left)
        right=copy.deepcopy(left)
        right["entries"][0]["package_sha256"]="a"*64
        new_head=mod._digest(2,right["entries"][0]["recipient_id"],
            right["entries"][0]["recipient_key_id"],"a"*64,
            right["entries"][0]["receipt_nonce_hex"],
            right["entries"][0]["receipt_sha256"],head)
        right["entries"][0]["event_hash"]=new_head
        right["current_head"]=new_head
        right_delta_pin,right_manifest_pin=self._fork_pins(previous,right)
        self.db.unlink()
        result=mod.assess_review_delta_fork(
            previous,sha,head,left,left_delta_pin,left_head,left_manifest_pin,
            right,right_delta_pin,new_head,right_manifest_pin,1)
        self.assertTrue(result["assessment_valid"])
        self.assertTrue(result["fork_detected"])
        evidence=result["fork_evidence"]
        self.assertEqual(evidence["first_divergent_sequence"],2)
        self.assertEqual(evidence["previous_head"],head)
        self.assertEqual(evidence["left_delta_sha256"],left_delta_pin)
        self.assertEqual(evidence["right_delta_sha256"],right_delta_pin)
        self.assertNotEqual(evidence["left_event_hash"],
                            evidence["right_event_hash"])
        body=json.dumps(evidence,sort_keys=True,separators=(",",":"),
                        ensure_ascii=False,allow_nan=False).encode("utf-8")
        commitment=hashlib.sha256(
            b"PALACO-SAMPLING-HANDOFF-FORK-EVIDENCE-V1\x00"+body).hexdigest()
        self.assertEqual(result["fork_evidence_sha256"],commitment)
        self.assertEqual(result["state"],"quarantined")
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_offline_fork_assessment_accepts_identical_successors(self):
        previous,sha,head,created,left_head=self._delta_fixture()
        delta=created["delta"]
        delta_pin,manifest_pin=self._fork_pins(previous,delta)
        result=mod.assess_review_delta_fork(
            previous,sha,head,delta,delta_pin,left_head,manifest_pin,
            delta,delta_pin,left_head,manifest_pin,1)
        self.assertTrue(result["assessment_valid"])
        self.assertFalse(result["fork_detected"])
        self.assertNotIn("fork_evidence",result)
        self.assertNotIn("fork_evidence_sha256",result)
        self.assertEqual(result["state"],"pending-review")

    def test_offline_fork_assessment_denies_invalid_right_pin(self):
        previous,sha,head,created,left_head=self._delta_fixture()
        delta=created["delta"]
        delta_pin,manifest_pin=self._fork_pins(previous,delta)
        result=mod.assess_review_delta_fork(
            previous,sha,head,delta,delta_pin,left_head,manifest_pin,
            delta,delta_pin,left_head,"f"*64,1)
        self.assertFalse(result["assessment_valid"])
        self.assertFalse(result["fork_detected"])
        self.assertEqual(result["reason"],
                         "right-current-review-manifest-pin-mismatch")
        self.assertFalse(result["authorization_granted"])

    def test_offline_fork_assessment_accepts_prefix_extension(self):
        previous,sha,head,created,left_head=self._delta_fixture()
        left=created["delta"]
        left_pin,left_manifest_pin=self._fork_pins(previous,left)
        right=copy.deepcopy(left)
        entry=right["entries"][0]
        head3=mod._digest(3,entry["recipient_id"],entry["recipient_key_id"],
                          "b"*64,"c"*64,entry["receipt_sha256"],left_head)
        right["entries"].append(dict(entry,sequence=3,
            package_sha256="b"*64,receipt_nonce_hex="c"*64,
            previous_hash=left_head,event_hash=head3))
        right["current_receipts"]=3
        right["current_head"]=head3
        right_pin,right_manifest_pin=self._fork_pins(previous,right)
        result=mod.assess_review_delta_fork(
            previous,sha,head,left,left_pin,left_head,left_manifest_pin,
            right,right_pin,head3,right_manifest_pin,1)
        self.assertTrue(result["assessment_valid"])
        self.assertFalse(result["fork_detected"])
        self.assertEqual(result["shorter_receipts"],2)
        self.assertEqual(result["longer_receipts"],3)

    def _verified_fork_fixture(self):
        previous,sha,head,created,left_head=self._delta_fixture()
        left=created["delta"]
        left_delta_pin,left_manifest_pin=self._fork_pins(previous,left)
        right=copy.deepcopy(left)
        right["entries"][0]["package_sha256"]="a"*64
        right_head=mod._digest(2,right["entries"][0]["recipient_id"],
            right["entries"][0]["recipient_key_id"],"a"*64,
            right["entries"][0]["receipt_nonce_hex"],
            right["entries"][0]["receipt_sha256"],head)
        right["entries"][0]["event_hash"]=right_head
        right["current_head"]=right_head
        right_delta_pin,right_manifest_pin=self._fork_pins(previous,right)
        arguments=(previous,sha,head,left,left_delta_pin,left_head,
                   left_manifest_pin,right,right_delta_pin,right_head,
                   right_manifest_pin,1)
        assessed=mod.assess_review_delta_fork(*arguments)
        self.assertTrue(assessed["fork_detected"])
        return arguments,assessed

    def test_offline_fork_evidence_reverification_without_database(self):
        arguments,assessed=self._verified_fork_fixture()
        self.db.unlink()
        result=mod.verify_review_fork_evidence(
            *arguments,assessed["fork_evidence"],assessed["fork_evidence_sha256"])
        self.assertTrue(result["fork_evidence_valid"])
        self.assertTrue(result["fork_detected"])
        self.assertEqual(result["first_divergent_sequence"],2)
        self.assertEqual(result["state"],"quarantined")
        self.assertFalse(result["authorization_granted"])
        self.assertEqual(result["release_gate"],"HOLD")

    def test_offline_fork_evidence_rejects_tampered_or_wrong_pin(self):
        arguments,assessed=self._verified_fork_fixture()
        evidence=copy.deepcopy(assessed["fork_evidence"])
        evidence["first_divergent_sequence"]=3
        result=mod.verify_review_fork_evidence(
            *arguments,evidence,assessed["fork_evidence_sha256"])
        self.assertFalse(result["fork_evidence_valid"])
        self.assertEqual(result["reason"],
                         "fork-evidence-does-not-match-verified-branches")
        result=mod.verify_review_fork_evidence(
            *arguments,assessed["fork_evidence"],"f"*64)
        self.assertFalse(result["fork_evidence_valid"])
        self.assertEqual(result["reason"],"fork-evidence-pin-mismatch")
        result=mod.verify_review_fork_evidence(
            *arguments,assessed["fork_evidence"],None)
        self.assertEqual(result["reason"],"missing-independent-fork-evidence-pin")

    def test_offline_fork_evidence_rejects_invalid_branch_anchor(self):
        arguments,assessed=self._verified_fork_fixture()
        altered=list(arguments)
        altered[10]="f"*64
        result=mod.verify_review_fork_evidence(
            *altered,assessed["fork_evidence"],assessed["fork_evidence_sha256"])
        self.assertFalse(result["fork_evidence_valid"])
        self.assertEqual(result["reason"],
                         "fork-assessment-right-current-review-manifest-pin-mismatch")
        self.assertFalse(result["authorization_granted"])

    def test_offline_fork_evidence_rejects_nonconflicting_branches(self):
        arguments,assessed=self._verified_fork_fixture()
        altered=list(arguments)
        altered[7]=altered[3]
        altered[8]=altered[4]
        altered[9]=altered[5]
        altered[10]=altered[6]
        result=mod.verify_review_fork_evidence(
            *altered,assessed["fork_evidence"],assessed["fork_evidence_sha256"])
        self.assertFalse(result["fork_evidence_valid"])
        self.assertEqual(result["reason"],"no-conflicting-review-delta-branches")
        self.assertFalse(result["fork_detected"])

    def test_delta_rejects_malformed_scalar_fields_before_hashing(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        for field,value in (("recipient_key_id",["a"*64]),
                            ("package_sha256","f"*100000),
                            ("receipt_nonce_hex",None),
                            ("recipient_id",{"unexpected":"object"}),
                            ("sequence",True),
                            ("event_hash","not-hex")):
            with self.subTest(field=field):
                delta=copy.deepcopy(created["delta"])
                delta["entries"][0][field]=value
                with patch.object(mod,"_delta_hash",
                                  side_effect=AssertionError("hashed invalid input")):
                    result=mod.verify_review_delta(
                        previous,sha,head,delta,created["delta_sha256"],
                        current_head,1)
                self.assertFalse(result["delta_valid"])
                self.assertEqual(result["reason"],"invalid-review-delta-entry")
                self.assertFalse(result["authorization_granted"])

    def test_delta_rejects_wrong_sequence_before_digesting(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        delta=copy.deepcopy(created["delta"])
        delta["entries"][0]["sequence"]=3
        with patch.object(mod,"_delta_hash",
                          side_effect=AssertionError("hashed invalid sequence")):
            result=mod.verify_review_delta(
                previous,sha,head,delta,created["delta_sha256"],
                current_head,1)
        self.assertEqual(result["reason"],"invalid-review-delta-entry")

    def test_delta_json_decoding_accepts_bounded_verified_bytes(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        self.db.unlink()
        result=mod.verify_review_delta_json(
            previous,sha,head,raw,created["delta_sha256"],current_head,1)
        self.assertTrue(result["delta_valid"])
        self.assertEqual(result["state"],"pending-review")
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_delta_json_rejects_oversized_or_nonbyte_input_before_parse(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        for raw,reason in (
            ("{}", "invalid-review-delta-json-type"),
            (bytearray(b"{}"),"invalid-review-delta-json-type"),
            (b"","review-delta-json-size-limit"),
            (b"x"*(mod.MAX_DELTA_JSON_BYTES+1),
             "review-delta-json-size-limit")):
            with self.subTest(reason=reason):
                with patch.object(mod.json,"loads",
                                  side_effect=AssertionError("parsed forbidden input")):
                    result=mod.verify_review_delta_json(
                        previous,sha,head,raw,created["delta_sha256"],
                        current_head,1)
                self.assertEqual(result["reason"],reason)
                self.assertFalse(result["authorization_granted"])

    def test_delta_json_rejects_ambiguous_duplicate_keys(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        duplicate_top=raw.replace(b'"schema_version":"0.1.0"',
                                  b'"schema_version":"0.1.0","schema_version":"0.1.0"',1)
        self.assertNotEqual(duplicate_top,raw)
        duplicate_nested=raw.replace(b'"sequence":2',
                                     b'"sequence":2,"sequence":2',1)
        self.assertNotEqual(duplicate_nested,raw)
        for invalid in (duplicate_top,duplicate_nested):
            result=mod.verify_review_delta_json(
                previous,sha,head,invalid,created["delta_sha256"],
                current_head,1)
            self.assertEqual(result["reason"],
                             "invalid-or-ambiguous-review-delta-json")
            self.assertFalse(result["delta_valid"])

    def test_delta_json_rejects_utf8_nonfinite_and_malformed_documents(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        for invalid in (b"\xff",b'{"unexpected":NaN}',b'{"unexpected":Infinity}',
                        b'{"unterminated":',b"[]]"):
            with self.subTest(invalid=invalid[:35]):
                result=mod.verify_review_delta_json(
                    previous,sha,head,invalid,created["delta_sha256"],
                    current_head,1)
                self.assertEqual(result["reason"],
                                 "invalid-or-ambiguous-review-delta-json")

    def test_delta_json_rejects_numeric_exponent_and_floating_values(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        for token in (b"2.0",b"2e0",b"2E+0"):
            with self.subTest(token=token):
                bad=raw.replace(b'"current_receipts":2',
                                b'"current_receipts":'+token,1)
                self.assertNotEqual(bad,raw)
                result=mod.verify_review_delta_json(
                    previous,sha,head,bad,created["delta_sha256"],
                    current_head,1)
                self.assertFalse(result["delta_valid"])
                self.assertEqual(result["reason"],
                                 "invalid-or-ambiguous-review-delta-json")
                self.assertFalse(result["authorization_granted"])

    def test_delta_json_rejects_oversized_integer_before_object_validation(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        for integer in (b"9"*11,b"9"*1000):
            with self.subTest(digits=len(integer)):
                bad=raw.replace(b'"current_receipts":2',
                                b'"current_receipts":'+integer,1)
                self.assertNotEqual(bad,raw)
                with patch.object(mod,"verify_review_delta",
                                  side_effect=AssertionError("unvalidated numeric token")):
                    result=mod.verify_review_delta_json(
                        previous,sha,head,bad,created["delta_sha256"],
                        current_head,1)
                self.assertFalse(result["delta_valid"])
                self.assertEqual(result["reason"],
                                 "invalid-or-ambiguous-review-delta-json")

    def test_delta_json_accepts_max_bounded_integer_token_but_denies_schema(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        bad=raw.replace(b'"current_receipts":2',
                        b'"current_receipts":9999999999',1)
        self.assertNotEqual(bad,raw)
        result=mod.verify_review_delta_json(
            previous,sha,head,bad,created["delta_sha256"],current_head,1)
        self.assertEqual(result["reason"],"invalid-review-delta-schema-or-pins")
        self.assertFalse(result["authorization_granted"])

    def test_strict_delta_json_accepts_independently_pinned_bytes(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        delta=created["delta"]
        current={"schema_version":"0.1.0",
                 "receipt_count":delta["current_receipts"],
                 "head_hash":current_head,
                 "entries":previous["entries"]+delta["entries"]}
        independent_pin=self._independently_pinned_manifest(current)
        raw=json.dumps(delta,sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        self.db.unlink()
        result=mod.verify_review_delta_json_with_manifest_pin(
            previous,sha,head,raw,created["delta_sha256"],
            current_head,independent_pin,1)
        self.assertTrue(result["delta_valid"])
        self.assertEqual(result["current_manifest_sha256"],independent_pin)
        self.assertEqual(result["state"],"pending-review")
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_strict_delta_json_denies_wrong_and_missing_independent_pin(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        for pin,reason in ((None,"missing-independent-current-manifest-pin"),
                           (True,"missing-independent-current-manifest-pin"),
                           ("f"*64,"current-review-manifest-pin-mismatch")):
            with self.subTest(pin=pin):
                result=mod.verify_review_delta_json_with_manifest_pin(
                    previous,sha,head,raw,created["delta_sha256"],
                    current_head,pin,1)
                self.assertFalse(result["delta_valid"])
                self.assertEqual(result["reason"],reason)
                self.assertFalse(result["authorization_granted"])

    def test_strict_delta_json_denies_duplicate_key_and_oversize_before_hash(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        malformed=raw.replace(b'"sequence":2',b'"sequence":2,"sequence":2',1)
        self.assertNotEqual(malformed,raw)
        result=mod.verify_review_delta_json_with_manifest_pin(
            previous,sha,head,malformed,created["delta_sha256"],
            current_head,"a"*64,1)
        self.assertFalse(result["delta_valid"])
        self.assertEqual(result["reason"],"invalid-or-ambiguous-review-delta-json")
        with patch.object(mod.json,"loads",
                          side_effect=AssertionError("parsed oversized payload")):
            result=mod.verify_review_delta_json_with_manifest_pin(
                previous,sha,head,b"x"*(mod.MAX_DELTA_JSON_BYTES+1),
                created["delta_sha256"],current_head,"a"*64,1)
        self.assertEqual(result["reason"],"review-delta-json-size-limit")

    def test_strict_delta_json_denies_wrong_delta_hash_without_authority(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        raw=json.dumps(created["delta"],sort_keys=True,
                       separators=(",",":")).encode("utf-8")
        result=mod.verify_review_delta_json_with_manifest_pin(
            previous,sha,head,raw,"f"*64,current_head,"a"*64,1)
        self.assertFalse(result["delta_valid"])
        self.assertEqual(result["reason"],"review-delta-digest-mismatch")
        self.assertEqual(result["release_gate"],"HOLD")

    def _anchor_history_fixture(self):
        previous,sha,head,created,current_head=self._delta_fixture()
        delta=created["delta"]
        current={"schema_version":"0.1.0",
                 "receipt_count":delta["current_receipts"],
                 "head_hash":current_head,
                 "entries":previous["entries"]+delta["entries"]}
        current_sha=self._independently_pinned_manifest(current)
        pins=[{"receipt_count":1,"head_hash":head,"manifest_sha256":sha},
              {"receipt_count":2,"head_hash":current_head,
               "manifest_sha256":current_sha}]
        return [previous,current],pins,current_head

    def test_review_anchor_history_valid_offline_growth(self):
        manifests,pins,head=self._anchor_history_fixture()
        self.db.unlink()
        result=mod.verify_review_anchor_history(manifests,pins,head,2)
        self.assertTrue(result["anchor_history_valid"])
        self.assertEqual(result["anchors"],2)
        self.assertEqual(result["latest_receipts"],2)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_review_anchor_history_rejects_rewound_final_checkpoint(self):
        manifests,pins,head=self._anchor_history_fixture()
        result=mod.verify_review_anchor_history(
            [manifests[1],manifests[0]],[pins[1],pins[0]],head,2)
        self.assertFalse(result["anchor_history_valid"])
        self.assertEqual(result["reason"],"review-anchor-history-rollback")
        result=mod.verify_review_anchor_history(
            [manifests[0]],[pins[0]],head,2)
        self.assertEqual(result["reason"],"review-anchor-history-rollback")

    def test_review_anchor_history_rejects_rewritten_authenticated_pin(self):
        manifests,pins,head=self._anchor_history_fixture()
        altered=copy.deepcopy(pins)
        altered[1]["manifest_sha256"]="f"*64
        result=mod.verify_review_anchor_history(manifests,altered,head,2)
        self.assertFalse(result["anchor_history_valid"])
        self.assertEqual(result["reason"],"anchor-review-manifest-digest-mismatch")
        self.assertFalse(result["authorization_granted"])

    def test_review_anchor_history_rejects_duplicate_count_split_view(self):
        manifests,pins,head=self._anchor_history_fixture()
        altered=copy.deepcopy(manifests[0])
        entry=altered["entries"][0]
        entry["recipient_id"]="other-reviewer"
        alternate=mod._digest(1,entry["recipient_id"],entry["recipient_key_id"],
                              entry["package_sha256"],entry["receipt_nonce_hex"],
                              entry["receipt_sha256"],mod.GENESIS)
        entry["event_hash"]=alternate
        altered["head_hash"]=alternate
        alternate_pin={"receipt_count":1,"head_hash":alternate,
                       "manifest_sha256":self._independently_pinned_manifest(altered)}
        result=mod.verify_review_anchor_history(
            [manifests[0],altered],[pins[0],alternate_pin],alternate,1)
        self.assertFalse(result["anchor_history_valid"])
        self.assertEqual(result["reason"],"review-anchor-history-equivocation")

    def test_review_anchor_history_bounds_and_strict_pin_types(self):
        manifests,pins,head=self._anchor_history_fixture()
        self.assertEqual(mod.verify_review_anchor_history(
            manifests,pins,head,True)["reason"],
            "missing-independent-anchor-history-pin")
        self.assertEqual(mod.verify_review_anchor_history(
            manifests,pins+[pins[-1]],head,1)["reason"],
            "invalid-review-anchor-history")
        many=[manifests[0]]*(mod.MAX_REVIEW_ANCHORS+1)
        many_pins=[pins[0]]*len(many)
        self.assertEqual(mod.verify_review_anchor_history(
            many,many_pins,head,1)["reason"],
            "invalid-review-anchor-history")
        altered=copy.deepcopy(pins)
        altered[0]["receipt_count"]=True
        self.assertEqual(mod.verify_review_anchor_history(
            manifests,altered,head,1)["reason"],
            "invalid-independent-review-anchor")

    def test_exact_terminal_anchor_accepts_independent_pin(self):
        manifests,pins,head=self._anchor_history_fixture()
        expected=copy.deepcopy(pins[-1])
        self.db.unlink()
        result=mod.verify_review_anchor_history_with_latest_pin(
            manifests,pins,expected)
        self.assertTrue(result["anchor_history_valid"])
        self.assertEqual(result["manifest_sha256"],expected["manifest_sha256"])
        self.assertEqual(result["latest_receipts"],2)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_exact_terminal_anchor_rejects_replayed_older_checkpoint(self):
        manifests,pins,head=self._anchor_history_fixture()
        result=mod.verify_review_anchor_history_with_latest_pin(
            manifests[:1],pins[:1],pins[-1])
        self.assertFalse(result["anchor_history_valid"])
        self.assertEqual(result["reason"],"review-anchor-history-rollback")
        self.assertFalse(result["authorization_granted"])

    def test_exact_terminal_anchor_rejects_wrong_manifest_digest(self):
        manifests,pins,head=self._anchor_history_fixture()
        expected=dict(pins[-1],manifest_sha256="f"*64)
        result=mod.verify_review_anchor_history_with_latest_pin(
            manifests,pins,expected)
        self.assertFalse(result["anchor_history_valid"])
        self.assertEqual(result["reason"],"latest-review-anchor-pin-mismatch")

    def test_exact_terminal_anchor_rejects_missing_or_malformed_pin(self):
        manifests,pins,head=self._anchor_history_fixture()
        for invalid in (None,True,{},dict(pins[-1],receipt_count=True),
                        dict(pins[-1],manifest_sha256="bad"),
                        dict(pins[-1],authorization_granted=True)):
            with self.subTest(invalid=invalid):
                result=mod.verify_review_anchor_history_with_latest_pin(
                    manifests,pins,invalid)
                self.assertFalse(result["anchor_history_valid"])
                self.assertEqual(result["reason"],
                                 "missing-independent-latest-review-anchor")

    def test_anchor_advance_accepts_new_independently_pinned_records(self):
        manifests,pins,head=self._anchor_history_fixture()
        self.db.unlink()
        result=mod.verify_review_anchor_advance(
            manifests[0],pins[0],manifests[1],pins[1],copy.deepcopy(pins[1]))
        self.assertTrue(result["anchor_advance_valid"])
        self.assertEqual(result["previous_receipts"],1)
        self.assertEqual(result["current_receipts"],2)
        self.assertEqual(result["state"],"pending-review")
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])

    def test_anchor_advance_rejects_replayed_identical_checkpoint(self):
        manifests,pins,head=self._anchor_history_fixture()
        result=mod.verify_review_anchor_advance(
            manifests[0],pins[0],manifests[0],pins[0],pins[0])
        self.assertFalse(result["anchor_advance_valid"])
        self.assertEqual(result["reason"],
                         "review-anchor-advance-requires-new-receipts")
        self.assertFalse(result["authorization_granted"])

    def test_anchor_advance_rejects_rollback_from_newer_checkpoint(self):
        manifests,pins,head=self._anchor_history_fixture()
        result=mod.verify_review_anchor_advance(
            manifests[1],pins[1],manifests[0],pins[0],pins[0])
        self.assertFalse(result["anchor_advance_valid"])
        self.assertEqual(result["reason"],"review-anchor-history-rollback")

    def test_anchor_advance_rejects_untrusted_latest_pin(self):
        manifests,pins,head=self._anchor_history_fixture()
        bad=dict(pins[1],manifest_sha256="f"*64)
        result=mod.verify_review_anchor_advance(
            manifests[0],pins[0],manifests[1],pins[1],bad)
        self.assertFalse(result["anchor_advance_valid"])
        self.assertEqual(result["reason"],"latest-review-anchor-pin-mismatch")
        self.assertFalse(result["authorization_granted"])

    def test_anchor_advance_rejects_rewritten_prior_history(self):
        manifests,pins,head=self._anchor_history_fixture()
        forged=copy.deepcopy(manifests[1])
        first=forged["entries"][0]
        first["recipient_id"]="alternate-reviewer"
        first["event_hash"]=mod._digest(
            1,first["recipient_id"],first["recipient_key_id"],
            first["package_sha256"],first["receipt_nonce_hex"],
            first["receipt_sha256"],mod.GENESIS)
        following=forged["entries"][1]
        following["previous_hash"]=first["event_hash"]
        following["event_hash"]=mod._digest(
            2,following["recipient_id"],following["recipient_key_id"],
            following["package_sha256"],following["receipt_nonce_hex"],
            following["receipt_sha256"],first["event_hash"])
        forged["head_hash"]=following["event_hash"]
        forged_pin={"receipt_count":2,"head_hash":forged["head_hash"],
                    "manifest_sha256":self._independently_pinned_manifest(forged)}
        result=mod.verify_review_anchor_advance(
            manifests[0],pins[0],forged,forged_pin,forged_pin)
        self.assertFalse(result["anchor_advance_valid"])
        self.assertEqual(result["reason"],"anchor-review-manifest-history-rewritten")

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
