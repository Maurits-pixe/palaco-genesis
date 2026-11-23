"""Signed historical sampling checkpoint succession with pinned prefixes."""
import base64
import copy
import importlib.util
import sqlite3
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "sampling_succession_fixture",ROOT/"tests"/"test_signed_sampling_ledger_checkpoint.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "sampling_succession",ROOT/"tools"/"sampling_checkpoint_succession.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SamplingCheckpointSuccessionTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.SignedSamplingLedgerCheckpointTests(
            methodName="test_valid_quorum_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.records=[self.make()]
        self.genesis=mod.record_digest(self.records[0])
        self.head=self.genesis

    def make(self,revision=1,previous=mod.GENESIS,checkpoint=None,witnesses=None):
        body={"schema_version":"0.1.0","revision":revision,
              "checkpoint":copy.deepcopy(self.f.checkpoint if checkpoint is None else checkpoint),
              "witnesses":copy.deepcopy(self.f.envelopes if witnesses is None else witnesses),
              "previous_record_sha256":previous}
        mod.canonical(body)
        return {"record":body}

    def check(self,records=None,genesis=None,head=None,minimum=1,
              ledger_head=None,ledger_floor=1,roots=None,orgs=None,
              revoked=None,required=2):
        result=mod.verify(
            self.f.f.db,self.records if records is None else records,
            self.f.roots if roots is None else roots,
            self.f.orgs if orgs is None else orgs,
            set() if revoked is None else revoked,required,
            self.genesis if genesis is None else genesis,
            self.head if head is None else head,minimum,
            self.f.recorded["head_hash"] if ledger_head is None else ledger_head,
            ledger_floor)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_valid_genesis_pending_only(self):
        r=self.check()
        self.assertTrue(r["sampling_succession_valid"])
        self.assertEqual(r["revisions"],1)

    def test_missing_records(self):
        self.assertEqual(self.check(records=[])["reason"],"invalid-sampling-succession-length")

    def test_wrong_pinned_genesis(self):
        self.assertEqual(self.check(genesis="f"*64)["reason"],"untrusted-succession-genesis")

    def test_wrong_pinned_head(self):
        self.assertEqual(self.check(head="f"*64)["reason"],"sampling-succession-head-mismatch")

    def test_revision_floor(self):
        self.assertEqual(self.check(minimum=2)["reason"],"sampling-succession-rollback")

    def test_wrong_ledger_head(self):
        self.assertEqual(self.check(ledger_head="f"*64)["reason"],"sampling-ledger-head-mismatch")

    def test_ledger_rollback_floor(self):
        self.assertEqual(self.check(ledger_floor=2)["reason"],"sampling-ledger-rollback")

    def test_revoked_witness(self):
        self.assertEqual(self.check(revoked={self.f.keys[1]})["reason"],
                         "insufficient-eligible-succession-organizations")

    def test_missing_root(self):
        self.assertEqual(self.check(roots={self.f.keys[0]:self.f.roots[self.f.keys[0]]})["reason"],
                         "untrusted-succession-witness")

    def test_duplicate_witness(self):
        record=self.make(witnesses=[self.f.envelopes[0],self.f.envelopes[0]])
        self.assertEqual(self.check(records=[record])["reason"],"duplicate-succession-witness")

    def test_duplicate_organization(self):
        orgs=dict.fromkeys(self.f.keys,"sampling-audit-a")
        self.assertEqual(self.check(orgs=orgs)["reason"],
                         "insufficient-eligible-succession-organizations")

    def test_conflicting_validly_signed_checkpoint(self):
        cp=dict(self.f.checkpoint,ledger_head_sha256="f"*64)
        record=self.make(witnesses=[self.f.envelopes[0],self.f.sign(1,cp)])
        self.assertEqual(self.check(records=[record])["reason"],
                         "conflicting-succession-checkpoint")

    def test_invalid_witness_signature(self):
        witnesses=copy.deepcopy(self.f.envelopes)
        witnesses[1]["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(records=[self.make(witnesses=witnesses)])["reason"],
                         "invalid-succession-signature")

    def test_malformed_signature(self):
        witnesses=copy.deepcopy(self.f.envelopes)
        witnesses[1]["signature_b64"]="!"
        self.assertEqual(self.check(records=[self.make(witnesses=witnesses)])["reason"],
                         "invalid-succession-signature-format")

    def test_wrong_historical_prefix(self):
        cp=dict(self.f.checkpoint,ledger_head_sha256="f"*64)
        record=self.make(checkpoint=cp,witnesses=[self.f.sign(0,cp),self.f.sign(1,cp)])
        self.assertEqual(self.check(records=[record])["reason"],"sampling-succession-prefix-mismatch")

    def test_forged_ledger_evidence(self):
        cp=dict(self.f.checkpoint,latest_evidence_sha256="f"*64)
        record=self.make(checkpoint=cp,witnesses=[self.f.sign(0,cp),self.f.sign(1,cp)])
        self.assertEqual(self.check(records=[record])["reason"],"sampling-succession-prefix-mismatch")

    def test_gap_in_revision(self):
        record=self.make(revision=2)
        self.assertEqual(self.check(records=[record])["reason"],"sampling-succession-revision-gap")

    def test_wrong_previous_hash(self):
        record=self.make(previous="f"*64)
        self.assertEqual(self.check(records=[record])["reason"],"sampling-succession-link-mismatch")

    def test_second_revision_without_new_ledger_batch_denied(self):
        second=self.make(revision=2,previous=self.genesis)
        self.assertEqual(self.check(records=[self.records[0],second])["reason"],
                         "sampling-succession-batch-rollback")

    def test_added_authority_field_denied(self):
        bad=copy.deepcopy(self.records)
        bad[0]["record"]["authorization_granted"]=True
        self.assertEqual(self.check(records=bad)["reason"],"invalid-sampling-succession-record")

    def test_boolean_revision_denied(self):
        bad=copy.deepcopy(self.records)
        bad[0]["record"]["revision"]=True
        self.assertEqual(self.check(records=bad)["reason"],"invalid-sampling-succession-revision")

    def test_tampered_nonce_index_denied(self):
        with sqlite3.connect(self.f.f.db) as conn:
            conn.execute("DELETE FROM archive_sample_nonces")
        self.assertEqual(self.check()["reason"],"sampling-ledger-integrity-failed")

    def test_missing_ledger_denied(self):
        self.f.f.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-sampling-ledger")

    def test_invalid_organization_policy(self):
        orgs=dict(self.f.orgs)
        orgs[self.f.keys[0]]="../bad"
        self.assertEqual(self.check(orgs=orgs)["reason"],"invalid-succession-organization-policy")

    def test_boolean_quorum_denied(self):
        self.assertEqual(self.check(required=True)["reason"],"missing-independent-succession-witness-policy")


if __name__=="__main__":
    unittest.main()
