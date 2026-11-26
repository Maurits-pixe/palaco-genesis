"""Adversarial tests: signed custody claim is not proof of storage."""
import base64
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "external_custody_archive_fixture",ROOT/"tests"/"test_delegation_receipt_archive.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "external_custody_claim",ROOT/"tools"/"external_archive_custody_claim.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ExternalArchiveCustodyClaimTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.DelegationReceiptArchiveTests(methodName="test_signed_archive_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.nonce="a"*64
        self.challenge={
            "schema_version":"0.1.0","requester_id":"audit-requester",
            "nonce_hex":self.nonce,"issued_epoch":100,
            "expires_epoch":200,"archive_head_sha256":self.f.latest,
            "archive_records":1,"audit_head_sha256":self.f.f.recorded["head_hash"]
        }
        self.response=self.make_response(self.challenge)

    def make_response(self,challenge,signer=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        use=self.f.custodian if signer is None else signer
        key=self.f.key
        body={"challenge":copy.deepcopy(challenge),"custodian_key_id":key,
              "custody_claim":mod.CLAIM,"signature_b64":""}
        msg=mod.canonical_response(body)
        body["signature_b64"]=base64.b64encode(use.sign(mod.DOMAIN+msg)).decode()
        return body

    def check(self,challenge=None,response=None,requester="audit-requester",
              nonce=None,now=150,used=None,head=None,roots=None,revoked=None):
        result=mod.verify(
            self.f.f.f.f.db,self.f.archive,self.f.f.roots,self.f.f.orgs,
            set(),2,self.f.roots if roots is None else roots,self.f.orgs,
            set() if revoked is None else revoked,{self.f.key},
            self.f.genesis,self.f.latest if head is None else head,1,
            self.f.f.recorded["head_hash"],1,
            self.challenge if challenge is None else challenge,
            self.response if response is None else response,
            requester,self.nonce if nonce is None else nonce,now,
            set() if used is None else used)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_valid_claim_still_pending_only(self):
        self.assertTrue(self.check()["custody_claim_valid"])

    def test_unknown_nonce_denied(self):
        self.assertEqual(self.check(nonce="f"*64)["reason"],"custody-challenge-not-requested")

    def test_reused_nonce_denied(self):
        self.assertEqual(self.check(used={self.nonce})["reason"],"custody-challenge-replay")

    def test_expired_challenge_denied(self):
        self.assertEqual(self.check(now=201)["reason"],"custody-challenge-expired-or-future")

    def test_future_challenge_denied(self):
        self.assertEqual(self.check(now=99)["reason"],"custody-challenge-expired-or-future")

    def test_boolean_clock_denied(self):
        self.assertEqual(self.check(now=True)["reason"],"missing-independent-challenge-policy")

    def test_requester_mismatch_denied(self):
        self.assertEqual(self.check(requester="other-requester")["reason"],
                         "custody-challenge-not-requested")

    def test_unauthorized_custody_claim_denied(self):
        invalid=copy.deepcopy(self.response)
        invalid["custody_claim"]="authorizes-recovery"
        self.assertEqual(self.check(response=invalid)["reason"],"invalid-custody-claim")

    def test_signature_corruption_denied(self):
        invalid=copy.deepcopy(self.response)
        invalid["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(response=invalid)["reason"],"invalid-custody-signature")

    def test_invalid_signature_encoding_denied(self):
        invalid=copy.deepcopy(self.response)
        invalid["signature_b64"]="!"
        self.assertEqual(self.check(response=invalid)["reason"],"invalid-custody-signature-format")

    def test_tampered_response_challenge_denied(self):
        invalid=copy.deepcopy(self.response)
        invalid["challenge"]["nonce_hex"]="b"*64
        self.assertEqual(self.check(response=invalid)["reason"],"custody-challenge-response-mismatch")

    def test_signed_wrong_archive_head_denied(self):
        altered=copy.deepcopy(self.challenge)
        altered["archive_head_sha256"]="f"*64
        reply=self.make_response(altered)
        self.assertEqual(self.check(challenge=altered,response=reply)["reason"],
                         "custody-challenge-archive-binding-mismatch")

    def test_untrusted_custodian_denied(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-archive-custodian")

    def test_revoked_custodian_denied(self):
        self.assertEqual(self.check(revoked={self.f.key})["reason"],"archive-custodian-revoked")

    def test_wrong_external_history_pin_denied(self):
        self.assertEqual(self.check(head="f"*64)["reason"],"custody-challenge-archive-binding-mismatch")

    def test_reject_added_authority_field(self):
        altered=copy.deepcopy(self.response)
        altered["authorization_granted"]=True
        self.assertEqual(self.check(response=altered)["reason"],"invalid-custody-response-schema")

    def test_reject_short_nonce(self):
        altered=copy.deepcopy(self.challenge)
        altered["nonce_hex"]="a"*32
        self.assertEqual(self.check(challenge=altered)["reason"],"invalid-custody-nonce")

    def test_reject_expiry_before_issue(self):
        altered=copy.deepcopy(self.challenge)
        altered["expires_epoch"]=100
        self.assertEqual(self.check(challenge=altered)["reason"],"invalid-custody-interval")


if __name__=="__main__":
    unittest.main()
