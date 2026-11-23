"""Signed sampling ledger checkpoints: independent organizations and fail-closed tests."""
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
    "sampling_ledger_checkpoint_fixture",ROOT/"tests"/"test_archive_sampling_evidence_ledger.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "signed_sampling_ledger_checkpoint",ROOT/"tools"/"signed_sampling_ledger_checkpoint.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedSamplingLedgerCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.ArchiveSamplingEvidenceLedgerTests(methodName="test_valid_batch_pending")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.recorded=self.f.record()
        self.assertTrue(self.recorded["recorded"])
        self.signers=[
            Ed25519PrivateKey.from_private_bytes(bytes(range(34,66))),
            Ed25519PrivateKey.from_private_bytes(bytes(range(67,99)))
        ]  # TEST ONLY, not operational witness secrets.
        self.keys=[]
        self.roots={}
        self.orgs={}
        for signer,org in zip(self.signers,("sampling-audit-a","sampling-audit-b")):
            public=signer.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw)
            key=hashlib.sha256(public).hexdigest()
            self.keys.append(key)
            self.roots[key]=public
            self.orgs[key]=org
        self.checkpoint={"schema_version":"0.1.0",
                         "ledger_head_sha256":self.recorded["head_hash"],
                         "batch_count":1,
                         "latest_manifest_sha256":self.f.f.f.digest,
                         "latest_evidence_sha256":self.recorded["evidence_sha256"]}
        self.envelopes=[self.sign(0),self.sign(1)]

    def sign(self,index,body=None):
        item=copy.deepcopy(self.checkpoint if body is None else body)
        signature=self.signers[index].sign(mod.DOMAIN+mod.canonical(item))
        return {"checkpoint":item,"witness_key_id":self.keys[index],
                "signature_b64":base64.b64encode(signature).decode()}

    def check(self,envelopes=None,head=None,minimum=1,roots=None,orgs=None,
              revoked=None,required=2):
        result=mod.verify(
            self.f.db,self.envelopes if envelopes is None else envelopes,
            self.roots if roots is None else roots,
            self.orgs if orgs is None else orgs,
            set() if revoked is None else revoked,required,
            self.recorded["head_hash"] if head is None else head,minimum)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_valid_quorum_pending_only(self):
        r=self.check()
        self.assertTrue(r["sampling_checkpoint_valid"])
        self.assertEqual(r["organizations"],2)

    def test_reverse_order_valid(self):
        self.assertTrue(self.check(list(reversed(self.envelopes)))["sampling_checkpoint_valid"])

    def test_single_witness_denied(self):
        self.assertEqual(self.check([self.envelopes[0]])["reason"],"invalid-sampling-witness-count")

    def test_duplicate_witness_denied(self):
        self.assertEqual(self.check([self.envelopes[0],self.envelopes[0]])["reason"],
                         "duplicate-sampling-witness")

    def test_two_keys_same_organization_denied(self):
        orgs=dict.fromkeys(self.keys,"sampling-audit-a")
        self.assertEqual(self.check(orgs=orgs)["reason"],
                         "insufficient-eligible-sampling-organizations")

    def test_revoked_witness_denied(self):
        self.assertEqual(self.check(revoked={self.keys[1]})["reason"],
                         "insufficient-eligible-sampling-organizations")

    def test_missing_trust_root_denied(self):
        self.assertEqual(self.check(roots={self.keys[0]:self.roots[self.keys[0]]})["reason"],
                         "untrusted-sampling-witness")

    def test_unknown_witness_denied(self):
        orgs={self.keys[0]:"sampling-audit-a","f"*64:"sampling-audit-b"}
        self.assertEqual(self.check(orgs=orgs)["reason"],"sampling-witness-not-allowed")

    def test_signed_conflicting_head_denied(self):
        body=dict(self.checkpoint,ledger_head_sha256="f"*64)
        self.assertEqual(self.check([self.envelopes[0],self.sign(1,body)])["reason"],
                         "conflicting-sampling-checkpoint")

    def test_signed_conflicting_batch_count_denied(self):
        body=dict(self.checkpoint,batch_count=2)
        self.assertEqual(self.check([self.envelopes[0],self.sign(1,body)])["reason"],
                         "conflicting-sampling-checkpoint")

    def test_signed_conflicting_evidence_denied(self):
        body=dict(self.checkpoint,latest_evidence_sha256="f"*64)
        self.assertEqual(self.check([self.envelopes[0],self.sign(1,body)])["reason"],
                         "conflicting-sampling-checkpoint")

    def test_tampered_signature_denied(self):
        values=copy.deepcopy(self.envelopes)
        values[1]["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(values)["reason"],"invalid-sampling-witness-signature")

    def test_malformed_signature_denied(self):
        values=copy.deepcopy(self.envelopes)
        values[1]["signature_b64"]="!"
        self.assertEqual(self.check(values)["reason"],"invalid-sampling-witness-signature-format")

    def test_tampered_unsigned_checkpoint_denied(self):
        values=copy.deepcopy(self.envelopes)
        values[1]["checkpoint"]["latest_manifest_sha256"]="f"*64
        self.assertEqual(self.check(values)["reason"],"invalid-sampling-witness-signature")

    def test_authorization_flag_denied(self):
        values=copy.deepcopy(self.envelopes)
        values[0]["checkpoint"]["authorization_granted"]=True
        self.assertEqual(self.check(values)["reason"],"invalid-sampling-checkpoint-schema")

    def test_boolean_count_denied(self):
        values=copy.deepcopy(self.envelopes)
        values[0]["checkpoint"]["batch_count"]=True
        self.assertEqual(self.check(values)["reason"],"invalid-sampling-checkpoint-count")

    def test_wrong_external_head_denied(self):
        self.assertEqual(self.check(head="f"*64)["reason"],"sampling-ledger-head-mismatch")

    def test_rollback_floor_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"],"sampling-ledger-rollback")

    def test_boolean_quorum_denied(self):
        self.assertEqual(self.check(required=True)["reason"],"missing-independent-sampling-witness-policy")

    def test_missing_external_head_denied(self):
        result=mod.verify(self.f.db,self.envelopes,self.roots,self.orgs,set(),2,None,1)
        self.assertEqual(result["reason"],"missing-independent-sampling-checkpoint-pin")

    def test_corrupt_ledger_hash_denied(self):
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("UPDATE archive_sample_batches SET event_hash=?",("f"*64,))
        self.assertEqual(self.check()["reason"],"sampling-ledger-integrity-failed")

    def test_missing_nonce_index_denied(self):
        with sqlite3.connect(self.f.db) as conn:
            conn.execute("DELETE FROM archive_sample_nonces")
        self.assertEqual(self.check()["reason"],"sampling-ledger-integrity-failed")

    def test_missing_ledger_denied(self):
        self.f.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-sampling-ledger")

    def test_wrong_organization_schema_denied(self):
        orgs=dict(self.orgs)
        orgs[self.keys[0]]="../invalid"
        self.assertEqual(self.check(orgs=orgs)["reason"],
                         "invalid-sampling-witness-organization")


if __name__=="__main__":
    unittest.main()
