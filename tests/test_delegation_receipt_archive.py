"""Signed archive statements cannot become authority or bypass external pins."""
import base64
import copy
import hashlib
import importlib.util
import sqlite3
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "archive_fixture",ROOT/"tests"/"test_signed_delegation_receipt_audit_anchor.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "receipt_archive",ROOT/"tools"/"delegation_receipt_archive.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DelegationReceiptArchiveTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.SignedDelegationReceiptAuditAnchorTests(
            methodName="test_valid_two_independent_witnesses_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.custodian=Ed25519PrivateKey.from_private_bytes(bytes(range(91,123))) # TEST ONLY
        pub=self.custodian.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.key=hashlib.sha256(pub).hexdigest()
        self.roots={self.key:pub}
        self.orgs={self.key:"independent-archive"}
        self.archive=[self.signed_record()]
        self.genesis=mod.record_digest(self.archive[0])
        self.latest=self.genesis

    def signed_record(self,sequence=1,previous=mod.ZERO,
                      checkpoint=None,witnesses=None):
        body={"schema_version":"0.1.0","sequence":sequence,
              "checkpoint":copy.deepcopy(self.f.envelopes[0]["checkpoint"]
                                          if checkpoint is None else checkpoint),
              "witnesses":copy.deepcopy(self.f.envelopes if witnesses is None else witnesses),
              "previous_record_sha256":previous}
        sig=self.custodian.sign(mod.DOMAIN+mod.canonical(body))
        return {"archive":body,"custodian_key_id":self.key,
                "signature_b64":base64.b64encode(sig).decode()}

    def check(self,archive=None,roots=None,orgs=None,revoked=None,allowed=None,
              genesis=None,latest=None,min_records=1,audit_head=None,
              min_receipts=1,witness_roots=None,witness_orgs=None,
              witness_revoked=None):
        result=mod.verify(
            self.f.f.f.db,self.archive if archive is None else archive,
            self.f.roots if witness_roots is None else witness_roots,
            self.f.orgs if witness_orgs is None else witness_orgs,
            set() if witness_revoked is None else witness_revoked,2,
            self.roots if roots is None else roots,
            self.orgs if orgs is None else orgs,
            set() if revoked is None else revoked,
            {self.key} if allowed is None else allowed,
            self.genesis if genesis is None else genesis,
            self.latest if latest is None else latest,
            min_records,
            self.f.recorded["head_hash"] if audit_head is None else audit_head,
            min_receipts)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_signed_archive_pending_only(self):
        result=self.check()
        self.assertTrue(result["archive_valid"])
        self.assertEqual(result["archive_records"],1)

    def test_independent_genesis_pin_required(self):
        self.assertEqual(self.check(genesis="f"*64)["reason"],"untrusted-archive-genesis")

    def test_independent_head_pin_required(self):
        self.assertEqual(self.check(latest="f"*64)["reason"],"archive-head-mismatch")

    def test_archive_floor_rejects_rollback(self):
        self.assertEqual(self.check(min_records=2)["reason"],"archive-rollback")

    def test_audit_count_floor_rejects_rollback(self):
        self.assertEqual(self.check(min_receipts=2)["reason"],"receipt-audit-rollback")

    def test_audit_head_pin_mismatch(self):
        self.assertEqual(self.check(audit_head="f"*64)["reason"],"receipt-audit-head-mismatch")

    def test_revoked_custodian(self):
        self.assertEqual(self.check(revoked={self.key})["reason"],"archive-custodian-revoked")

    def test_unknown_custodian_root(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-archive-custodian")

    def test_custodian_not_allowed(self):
        self.assertEqual(self.check(allowed=set())["reason"],"archive-custodian-not-allowed")

    def test_custodian_org_collides_with_witness_org(self):
        self.assertEqual(self.check(orgs={self.key:"archive-witness-a"})["reason"],
                         "archive-organization-role-collision")

    def test_tampered_custodian_signature(self):
        bad=copy.deepcopy(self.archive)
        bad[0]["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(archive=bad,genesis=mod.record_digest(bad[0]))["reason"],
                         "invalid-archive-signature")

    def test_malformed_custodian_signature(self):
        bad=copy.deepcopy(self.archive)
        bad[0]["signature_b64"]="!"
        self.assertEqual(self.check(archive=bad,genesis=mod.record_digest(bad[0]))["reason"],
                         "invalid-archive-signature-format")

    def test_tampered_witness_signature(self):
        bad=copy.deepcopy(self.f.envelopes)
        bad[0]["signature_b64"]=base64.b64encode(bytes(64)).decode()
        record=self.signed_record(witnesses=bad)
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "invalid-archived-signature")

    def test_authentic_but_conflicting_witness(self):
        bad=[self.f.envelopes[0],
             self.f.envelope(1,{"audit_head_sha256":"f"*64})]
        record=self.signed_record(witnesses=bad)
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "conflicting-archived-checkpoint")

    def test_unknown_archived_witness(self):
        bad=copy.deepcopy(self.f.envelopes)
        bad[1]["witness_key_id"]="f"*64
        record=self.signed_record(witnesses=bad)
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "archived-witness-not-allowed")

    def test_revoked_archived_witness(self):
        self.assertEqual(self.check(witness_revoked={self.f.ids[1]})["reason"],
                         "insufficient-archive-witness-organizations")

    def test_duplicate_archived_witness(self):
        record=self.signed_record(witnesses=[self.f.envelopes[0],self.f.envelopes[0]])
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "duplicate-archived-witness")

    def test_missing_archive(self):
        self.assertEqual(self.check(archive=[])["reason"],"invalid-archive-length")

    def test_additional_authority_flag_forbidden(self):
        bad=copy.deepcopy(self.archive)
        bad[0]["archive"]["authorization_granted"]=True
        self.assertEqual(self.check(archive=bad)["reason"],"invalid-archive-record-schema")

    def test_missing_local_receipt_index(self):
        with sqlite3.connect(self.f.f.f.db) as conn:
            conn.execute("DELETE FROM delegation_handoff_receipts")
        self.assertEqual(self.check()["reason"],"receipt-audit-integrity-failed")

    def test_archive_count_must_match_database_prefix(self):
        cp=copy.deepcopy(self.f.envelopes[0]["checkpoint"])
        cp["entries"]=2
        record=self.signed_record(checkpoint=cp)
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "archive-prefix-mismatch")

    def test_archive_sequence_gap(self):
        record=self.signed_record(sequence=2)
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "archive-sequence-gap")

    def test_wrong_predecessor_hash(self):
        record=self.signed_record(previous="f"*64)
        self.assertEqual(self.check(archive=[record],
            genesis=mod.record_digest(record),latest=mod.record_digest(record))["reason"],
            "archive-link-mismatch")


if __name__=="__main__":
    unittest.main()
