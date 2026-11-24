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
