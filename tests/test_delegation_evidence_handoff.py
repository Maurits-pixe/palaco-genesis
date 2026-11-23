"""Offline delegation evidence handoff, signed receipt and replay tests."""
import base64
import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "witness_handoff_fixture",ROOT/"tests"/"test_delegation_history_witness_checkpoint.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "delegation_evidence_handoff",ROOT/"tools"/"delegation_evidence_handoff.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DelegationEvidenceHandoffTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.DelegationWitnessCheckpointTests(
            methodName="test_two_witnesses_pending_only")
        self.f.setUp()
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db=Path(t.name)/"receipts.sqlite"
        self.recipient=Ed25519PrivateKey.from_private_bytes(bytes(range(70,102))) # TEST ONLY
        pub=self.recipient.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.rid=hashlib.sha256(pub).hexdigest()
        self.roots={self.rid:pub}
        self.prepared=mod.prepare(self.f.inputs,self.f.f.records,self.f.claims,
                                  self.f.roots,self.f.organizations,set(),2,"archive-alpha")
        self.assertTrue(self.prepared["package_prepared"])
        self.package=self.prepared["package"]
        self.digest=self.prepared["package_sha256"]

    def receipt(self, id="a"*32, recipient="archive-alpha", digest=None):
        body={"schema_version":"0.1.0","recipient_id":recipient,
              "package_sha256":self.digest if digest is None else digest,
              "receipt_id":id,"disposition":mod.DISPOSITION}
        sig=self.recipient.sign(mod.RECEIPT_DOMAIN+mod.canonical_receipt(body))
        return {"receipt":body,"recipient_key_id":self.rid,
                "signature_b64":base64.b64encode(sig).decode()}

    def verify(self,package=None,receipt=None,expected=None,recipient="archive-alpha",
               roots=None,revoked=None,allowed=None,inputs=None):
        result=mod.verify_receipt(
            self.f.inputs if inputs is None else inputs,self.f.f.records,
            self.package if package is None else package,
            self.receipt() if receipt is None else receipt,
            recipient,self.digest if expected is None else expected,
            self.f.roots,self.f.organizations,set(),2,
            self.roots if roots is None else roots,
            set() if revoked is None else revoked,
            {self.rid} if allowed is None else allowed)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def record(self,receipt=None):
        return mod.register_receipt(
            self.db,self.f.inputs,self.f.f.records,self.package,
            self.receipt() if receipt is None else receipt,
            "archive-alpha",self.digest,self.f.roots,
            self.f.organizations,set(),2,self.roots,set(),{self.rid})

    def test_valid_claim_stays_pending(self):
        self.assertTrue(self.verify()["receipt_valid"])

    def test_package_deterministic(self):
        p=mod.prepare(self.f.inputs,self.f.f.records,self.f.claims,
                      self.f.roots,self.f.organizations,set(),2,"archive-alpha")
        self.assertEqual(p["package_sha256"],self.digest)

    def test_invalid_recipient_rejected_in_prepare(self):
        self.assertEqual(mod.prepare(
            self.f.inputs,self.f.f.records,self.f.claims,self.f.roots,
            self.f.organizations,set(),2,"../escape")["reason"],"invalid-recipient")

    def test_prepare_requires_valid_witness_quorum(self):
        self.assertEqual(mod.prepare(
            self.f.inputs,self.f.f.records,self.f.claims[:1],self.f.roots,
            self.f.organizations,set(),2,"archive-alpha")["reason"],
            "invalid-witness-submission-count")

    def test_wrong_independently_expected_digest(self):
        self.assertEqual(self.verify(expected="f"*64)["reason"],"package-hash-mismatch")

    def test_wrong_expected_recipient(self):
        self.assertEqual(self.verify(recipient="archive-other")["reason"],"recipient-mismatch")

    def test_modified_package_fails_hash_check(self):
        p=copy.deepcopy(self.package)
        p["witnesses"][0]["signature_b64"]="modified"
        self.assertEqual(self.verify(package=p)["reason"],"package-hash-mismatch")

    def test_missing_witness_denied(self):
        p=copy.deepcopy(self.package)
        p["witnesses"]=p["witnesses"][:1]
        self.assertEqual(self.verify(package=p)["reason"],"invalid-handoff-package")

    def test_signed_receipt_wrong_digest_denied(self):
        self.assertEqual(self.verify(receipt=self.receipt(digest="f"*64))["reason"],
                         "receipt-binding-mismatch")

    def test_signed_receipt_wrong_recipient_denied(self):
        self.assertEqual(self.verify(receipt=self.receipt(recipient="archive-other"))["reason"],
                         "receipt-binding-mismatch")

    def test_invalid_signature_denied(self):
        r=self.receipt()
        r["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.verify(receipt=r)["reason"],"invalid-receipt-signature")

    def test_malformed_signature_denied(self):
        r=self.receipt()
        r["signature_b64"]="!"
        self.assertEqual(self.verify(receipt=r)["reason"],"invalid-receipt-signature-format")

    def test_revoked_recipient_key_denied(self):
        self.assertEqual(self.verify(revoked={self.rid})["reason"],"recipient-key-revoked")

    def test_untrusted_recipient_denied(self):
        self.assertEqual(self.verify(roots={})["reason"],"untrusted-recipient-key")

    def test_recipient_not_allowed_denied(self):
        self.assertEqual(self.verify(allowed=set())["reason"],"recipient-key-not-allowed")

    def test_unauthorized_disposition_denied(self):
        r=self.receipt()
        r["receipt"]["disposition"]="release-approved"
        self.assertEqual(self.verify(receipt=r)["reason"],"invalid-receipt-disposition")

    def test_replay_rejected(self):
        self.assertTrue(self.record()["recorded"])
        self.assertEqual(self.record()["reason"],"receipt-replay")

    def test_duplicate_package_different_receipt_denied(self):
        self.assertTrue(self.record()["recorded"])
        self.assertEqual(self.record(self.receipt(id="b"*32))["reason"],
                         "duplicate-package-receipt")

    def test_invalid_receipt_not_registered(self):
        r=self.receipt()
        r["signature_b64"]="!"
        self.assertEqual(self.record(r)["reason"],"invalid-receipt-signature-format")
        self.assertFalse(self.db.exists())

    def test_revoked_delegation_blocks_receipt(self):
        self.f.f.append()
        i=self.f.history_inputs()
        self.assertEqual(self.verify(inputs=i)["reason"],"delegation-revoked")

    def test_added_authority_field_denied(self):
        p=copy.deepcopy(self.package)
        p["authorization_granted"]=True
        self.assertEqual(self.verify(package=p)["reason"],"invalid-handoff-package")


if __name__=="__main__":
    unittest.main()
