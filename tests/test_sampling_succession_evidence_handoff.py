"""Sampling succession handoff: signed receipt and adversarial integrity checks."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "sampling_handoff_fixture",ROOT/"tests"/"test_sampling_checkpoint_succession.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "sampling_handoff_module",ROOT/"tools"/"sampling_succession_evidence_handoff.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SamplingSuccessionEvidenceHandoffTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.SamplingCheckpointSuccessionTests(methodName="test_valid_genesis_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.key=Ed25519PrivateKey.from_private_bytes(bytes(range(97,129))) # TEST ONLY
        public=self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw)
        self.key_id=hashlib.sha256(public).hexdigest()
        self.roots={self.key_id:public}
        self.nonce="b"*64
        result=self.prepare()
        self.assertTrue(result["package_prepared"])
        self.package=result["package"]
        self.digest=result["package_sha256"]
        self.receipt=self.sign()

    def prepare(self,recipient="archive-reviewer",records=None,genesis=None,
                revoked=None):
        return mod.prepare(
            self.f.f.f.db,self.f.records if records is None else records,
            self.f.f.roots,self.f.f.orgs,
            set() if revoked is None else revoked,2,
            self.f.genesis if genesis is None else genesis,self.f.head,1,
            self.f.f.recorded["head_hash"],1,recipient)

    def sign(self,body=None):
        claim={"schema_version":"0.1.0","recipient_id":"archive-reviewer",
               "package_sha256":self.digest,"receipt_nonce_hex":self.nonce,
               "disposition":mod.DISPOSITION}
        if body is not None:claim.update(body)
        raw=mod.canonical_receipt(claim)
        return {"receipt":claim,"recipient_key_id":self.key_id,
                "signature_b64":base64.b64encode(self.key.sign(mod.RECEIPT_DOMAIN+raw)).decode()}

    def check(self,package=None,receipt=None,expected=None,recipient="archive-reviewer",
              nonce=None,used=None,roots=None,allowed=None,revoked=None,
              witnesses_revoked=None,genesis=None,head=None):
        value=mod.verify_receipt(
            self.f.f.f.db,self.package if package is None else package,
            self.receipt if receipt is None else receipt,
            self.f.f.roots,self.f.f.orgs,
            set() if witnesses_revoked is None else witnesses_revoked,2,
            self.f.genesis if genesis is None else genesis,
            self.f.head if head is None else head,1,
            self.f.f.recorded["head_hash"],1,
            recipient,self.digest if expected is None else expected,
            self.nonce if nonce is None else nonce,
            set() if used is None else used,
            self.roots if roots is None else roots,
            {self.key_id} if allowed is None else allowed,
            set() if revoked is None else revoked)
        self.assertEqual(value["release_gate"],"HOLD")
        self.assertFalse(value["authorization_granted"])
        self.assertFalse(value["automatic_restore"])
        self.assertFalse(value["recovery_approved"])
        return value

    def test_valid_receipt_pending_only(self):
        self.assertTrue(self.check()["receipt_valid"])

    def test_deterministic_package_hash(self):
        self.assertEqual(self.prepare()["package_sha256"],self.digest)

    def test_prepare_invalid_recipient(self):
        self.assertEqual(self.prepare(recipient="../wrong")["reason"],"invalid-handoff-recipient")

    def test_prepare_invalid_witness_history(self):
        self.assertEqual(self.prepare(revoked={self.f.f.keys[1]})["reason"],
                         "insufficient-eligible-succession-organizations")

    def test_prepare_wrong_pin(self):
        self.assertEqual(self.prepare(genesis="f"*64)["reason"],"untrusted-succession-genesis")

    def test_wrong_expected_recipient(self):
        self.assertEqual(self.check(recipient="other")["reason"],"handoff-recipient-mismatch")

    def test_wrong_expected_package_hash(self):
        self.assertEqual(self.check(expected="f"*64)["reason"],"handoff-package-pin-mismatch")

    def test_changed_package_records(self):
        altered=copy.deepcopy(self.package)
        altered["records"][0]["record"]["checkpoint"]["latest_manifest_sha256"]="f"*64
        self.assertEqual(self.check(package=altered)["reason"],"invalid-handoff-package")

    def test_missing_package_record(self):
        altered=copy.deepcopy(self.package)
        altered["records"]=[]
        self.assertEqual(self.check(package=altered)["reason"],"invalid-handoff-package")

    def test_added_package_privilege(self):
        altered=dict(self.package,authorization_granted=True)
        self.assertEqual(self.check(package=altered)["reason"],"invalid-handoff-package")

    def test_wrong_package_history_head_pin(self):
        self.assertEqual(self.check(head="f"*64)["reason"],"handoff-history-pin-mismatch")

    def test_signed_wrong_recipient(self):
        claim=self.sign({"recipient_id":"other"})
        self.assertEqual(self.check(receipt=claim)["reason"],"handoff-receipt-binding-mismatch")

    def test_signed_wrong_digest(self):
        claim=self.sign({"package_sha256":"f"*64})
        self.assertEqual(self.check(receipt=claim)["reason"],"handoff-receipt-binding-mismatch")

    def test_signed_wrong_nonce(self):
        claim=self.sign({"receipt_nonce_hex":"f"*64})
        self.assertEqual(self.check(receipt=claim)["reason"],"handoff-receipt-binding-mismatch")

    def test_used_nonce(self):
        self.assertEqual(self.check(used={self.nonce})["reason"],"handoff-receipt-nonce-replayed")

    def test_unexpected_nonce(self):
        self.assertEqual(self.check(nonce="f"*64)["reason"],"handoff-receipt-binding-mismatch")

    def test_revoked_recipient_key(self):
        self.assertEqual(self.check(revoked={self.key_id})["reason"],"handoff-recipient-revoked")

    def test_unknown_recipient_key(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-handoff-recipient")

    def test_not_allowlisted_key(self):
        self.assertEqual(self.check(allowed=set())["reason"],"handoff-recipient-not-allowed")

    def test_tampered_signature(self):
        claim=copy.deepcopy(self.receipt)
        claim["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(receipt=claim)["reason"],"invalid-handoff-signature")

    def test_malformed_signature(self):
        claim=copy.deepcopy(self.receipt)
        claim["signature_b64"]="!"
        self.assertEqual(self.check(receipt=claim)["reason"],"invalid-handoff-signature-format")

    def test_authority_disposition_forbidden(self):
        claim=copy.deepcopy(self.receipt)
        claim["receipt"]["disposition"]="approve-restoration"
        self.assertEqual(self.check(receipt=claim)["reason"],"invalid-sampling-handoff-disposition")

    def test_receipt_extra_privilege(self):
        claim=dict(self.receipt,release_gate="OPEN")
        self.assertEqual(self.check(receipt=claim)["reason"],"invalid-sampling-handoff-receipt-envelope")

    def test_revoked_history_witness(self):
        self.assertEqual(self.check(witnesses_revoked={self.f.f.keys[1]})["reason"],
                         "insufficient-eligible-succession-organizations")

    def test_missing_ledgers(self):
        self.f.f.f.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-sampling-ledger")

    def test_recipient_witness_role_collision(self):
        claim=copy.deepcopy(self.receipt)
        claim["recipient_key_id"]=self.f.f.keys[0]
        self.assertEqual(self.check(receipt=claim)["reason"],"handoff-witness-recipient-key-collision")


if __name__=="__main__":
    unittest.main()
