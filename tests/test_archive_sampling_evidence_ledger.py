"""Archive sampling ledger: transactional proofs, replay and rollback."""
import copy
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "archive_ledger_fixture",ROOT/"tests"/"test_multi_sample_archive_availability.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "archive_sample_ledger",ROOT/"tools"/"archive_sampling_evidence_ledger.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ArchiveSamplingEvidenceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.MultiSampleArchiveAvailabilityTests(methodName="test_two_samples_pending_only")
        self.f.setUp()
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db=Path(tmp.name)/"sample-ledger.sqlite"

    def record(self,head=mod.GENESIS,min_batches=0,seed=None,
               requests=None,replies=None,roots=None,coverage=500000):
        result=mod.record(
            self.db,self.f.f.manifest,self.f.f.digest,"a"*64,
            self.f.seed if seed is None else seed,2,coverage,
            self.f.requests if requests is None else requests,
            self.f.replies if replies is None else replies,"audit-requester",
            150,self.f.f.roots if roots is None else roots,
            {self.f.f.kid},set(),head,min_batches)
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

    def test_valid_batch_pending(self):
        result=self.record()
        self.assertTrue(result["recorded"])
        self.assertEqual(result["batches"],1)
        self.assertTrue(self.inspect(result["head_hash"])["ledger_valid"])

    def test_identical_batch_is_not_accepted_twice(self):
        first=self.record()
        again=self.record(head=first["head_hash"],min_batches=1)
        self.assertFalse(again["recorded"])
        self.assertIn("replay",again["reason"])
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])

    def test_old_external_head_denied(self):
        self.record()
        self.assertEqual(self.record()["reason"],"sampling-ledger-head-mismatch")

    def test_external_count_floor_denied(self):
        self.record()
        self.assertEqual(self.inspect("f"*64,2)["reason"],"sampling-ledger-rollback")

    def test_tampered_chain_hash_denied(self):
        recorded=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE archive_sample_batches SET event_hash=?",("f"*64,))
        self.assertEqual(self.inspect(recorded["head_hash"])["reason"],"sampling-ledger-integrity-failed")

    def test_tampered_index_denied(self):
        recorded=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM archive_sample_nonces LIMIT 1")
        self.assertEqual(self.inspect(recorded["head_hash"])["reason"],"sampling-ledger-integrity-failed")

    def test_wrong_stored_population_denied(self):
        recorded=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE archive_sample_batches SET population=2")
        self.assertEqual(self.inspect(recorded["head_hash"])["reason"],"sampling-ledger-integrity-failed")

    def test_wrong_stored_sampling_index_denied(self):
        recorded=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE archive_sample_batches SET indices_json=?",("[1,1]",))
        self.assertEqual(self.inspect(recorded["head_hash"])["reason"],"sampling-ledger-integrity-failed")

    def test_missing_local_db_not_created_on_read(self):
        self.assertEqual(self.inspect("f"*64)["reason"],"missing-sampling-ledger")
        self.assertFalse(self.db.exists())

    def test_failed_signature_never_recorded(self):
        bad=copy.deepcopy(self.f.replies)
        bad[1]["signature_b64"]="!"
        result=self.record(replies=bad)
        self.assertFalse(result["recorded"])
        with sqlite3.connect(self.db) as conn:
            count=conn.execute("SELECT COUNT(*) FROM archive_sample_batches").fetchone()[0]
            nonce_count=conn.execute("SELECT COUNT(*) FROM archive_sample_nonces").fetchone()[0]
        self.assertEqual((count,nonce_count),(0,0))

    def test_partial_batch_never_recorded(self):
        self.assertFalse(self.record(replies=self.f.replies[:1])["recorded"])
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM archive_sample_batches").fetchone()[0],0)

    def test_unknown_signer_never_recorded(self):
        self.assertFalse(self.record(roots={})["recorded"])

    def test_inspection_requires_external_head(self):
        self.record()
        self.assertEqual(self.inspect(None)["reason"],"missing-independent-sampling-ledger-pin")

    def test_record_requires_independent_prior_pin(self):
        self.assertEqual(self.record(head=None)["reason"],"missing-independent-previous-ledger-pin")
        self.assertFalse(self.db.exists())

    def test_record_requires_independent_minimum(self):
        self.assertEqual(self.record(min_batches=True)["reason"],"missing-independent-previous-ledger-pin")

    def test_read_only_inspection(self):
        first=self.record()
        before=self.db.stat().st_size
        self.assertTrue(self.inspect(first["head_hash"])["ledger_valid"])
        self.assertEqual(self.db.stat().st_size,before)

    def test_tamper_blocks_next_write(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE archive_sample_batches SET previous_hash=?",("f"*64,))
        self.assertEqual(self.record(head=first["head_hash"],min_batches=1)["reason"],
                         "sampling-ledger-integrity-failed")

    def test_missing_nonce_index_blocks_next_write(self):
        first=self.record()
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM archive_sample_nonces")
        self.assertEqual(self.record(head=first["head_hash"],min_batches=1)["reason"],
                         "sampling-ledger-integrity-failed")

    def test_failed_coverage_not_recorded(self):
        self.assertEqual(self.record(coverage=800000)["reason"],"insufficient-multi-sample-coverage")

    def test_in_memory_database_forbidden(self):
        self.db=":memory:"
        self.assertEqual(self.record()["reason"],"persistent-ledger-required")

    def test_empty_ledger_cannot_pass_inspect(self):
        self.assertEqual(self.inspect(mod.GENESIS)["reason"],"missing-sampling-ledger")


if __name__=="__main__":
    unittest.main()
