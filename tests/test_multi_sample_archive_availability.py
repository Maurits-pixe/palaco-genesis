"""Multi-sample archive proof: unbiased selection and batch fail-closed tests."""
import base64
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
fixture_spec=importlib.util.spec_from_file_location(
    "multi_sample_fixture",ROOT/"tests"/"test_archive_content_availability.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "multi_sample_archive",ROOT/"tools"/"multi_sample_archive_availability.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class MultiSampleArchiveAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.ArchiveContentAvailabilityTests(
            methodName="test_valid_last_chunk_pending_only")
        self.f.setUp()
        self.seed="c"*64
        self.count=2
        self.selected=mod.indices(self.seed,self.f.digest,3,self.count)
        self.requests=[]
        self.replies=[]
        for ordinal,index in enumerate(self.selected):
            challenge={"schema_version":"0.1.0","requester_id":"audit-requester",
                       "nonce_hex":mod.nonce(self.seed,self.f.digest,ordinal),
                       "manifest_sha256":self.f.digest,"chunk_index":index,
                       "issued_epoch":100,"expires_epoch":200}
            self.requests.append(challenge)
            self.replies.append(self.f.answer(challenge,self.f.chunks[index]))

    def check(self,seed=None,count=2,coverage=500000,requests=None,replies=None,
              manifest=None,pin=None,archive=None,used=None,roots=None,
              allowed=None,revoked=None,now=150):
        result=mod.verify(
            self.f.manifest if manifest is None else manifest,
            self.f.digest if pin is None else pin,
            "a"*64 if archive is None else archive,
            self.seed if seed is None else seed,count,coverage,
            self.requests if requests is None else requests,
            self.replies if replies is None else replies,
            "audit-requester",now,set() if used is None else used,
            self.f.roots if roots is None else roots,
            {self.f.kid} if allowed is None else allowed,
            set() if revoked is None else revoked)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_two_samples_pending_only(self):
        result=self.check()
        self.assertTrue(result["multi_sample_valid"])
        self.assertEqual(result["sample_count"],2)
        self.assertEqual(result["coverage_ppm"],666666)

    def test_without_replacement(self):
        self.assertEqual(len(set(self.selected)),2)
        self.assertEqual(set(mod.indices(self.seed,self.f.digest,3,3)),{0,1,2})

    def test_deterministic_indices(self):
        self.assertEqual(mod.indices(self.seed,self.f.digest,3,2),self.selected)

    def test_independently_changed_seed_rejected(self):
        self.assertEqual(self.check(seed="f"*64)["reason"],"multi-sample-nonce-mismatch")

    def test_insufficient_coverage(self):
        self.assertEqual(self.check(coverage=700000)["reason"],"insufficient-multi-sample-coverage")

    def test_boolean_coverage_rejected(self):
        self.assertEqual(self.check(coverage=True)["reason"],"missing-independent-multi-sample-policy")

    def test_duplicate_sample_request_rejected(self):
        requests=[self.requests[0],self.requests[0]]
        self.assertEqual(self.check(requests=requests)["reason"],"multi-sample-index-mismatch")

    def test_missing_reply_denied(self):
        self.assertEqual(self.check(replies=self.replies[:1])["reason"],"incomplete-multi-sample-batch")

    def test_missing_request_denied(self):
        self.assertEqual(self.check(requests=self.requests[:1])["reason"],"incomplete-multi-sample-batch")

    def test_reordered_replies_rejected(self):
        self.assertEqual(self.check(replies=list(reversed(self.replies)))["reason"],
                         "multi-sample-verification-failed:content-response-challenge-mismatch")

    def test_modified_second_chunk_denied(self):
        replies=copy.deepcopy(self.replies)
        i=self.selected[1]
        chunk=b"x"*len(self.f.chunks[i])
        replies[1]=self.f.answer(self.requests[1],chunk)
        self.assertEqual(self.check(replies=replies)["reason"],
                         "multi-sample-verification-failed:content-chunk-hash-mismatch")

    def test_tampered_second_signature_denied(self):
        replies=copy.deepcopy(self.replies)
        replies[1]["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(replies=replies)["reason"],
                         "multi-sample-verification-failed:invalid-content-signature")

    def test_replayed_first_nonce_denied(self):
        self.assertEqual(self.check(used={self.requests[0]["nonce_hex"]})["reason"],
                         "multi-sample-verification-failed:content-challenge-replay")

    def test_replayed_second_nonce_denied(self):
        self.assertEqual(self.check(used={self.requests[1]["nonce_hex"]})["reason"],
                         "multi-sample-verification-failed:content-challenge-replay")

    def test_expired_window_denied(self):
        self.assertEqual(self.check(now=201)["reason"],
                         "multi-sample-verification-failed:content-challenge-expired-or-future")

    def test_untrusted_signer_denied(self):
        self.assertEqual(self.check(roots={})["reason"],
                         "multi-sample-verification-failed:untrusted-content-custodian")

    def test_revoked_signer_denied(self):
        self.assertEqual(self.check(revoked={self.f.kid})["reason"],
                         "multi-sample-verification-failed:content-custodian-revoked")

    def test_wrong_manifest_pin_denied(self):
        self.assertEqual(self.check(pin="f"*64)["reason"],"multi-sample-manifest-pin-mismatch")

    def test_wrong_archive_pin_denied(self):
        self.assertEqual(self.check(archive="f"*64)["reason"],"multi-sample-manifest-pin-mismatch")

    def test_sample_count_boolean_denied(self):
        self.assertEqual(self.check(count=True)["reason"],"invalid-multi-sample-selection-policy")

    def test_zero_sample_count_denied(self):
        self.assertEqual(self.check(count=0)["reason"],"invalid-multi-sample-selection-policy")

    def test_bad_seed_denied(self):
        self.assertEqual(self.check(seed="bad")["reason"],"invalid-multi-sample-selection-policy")

    def test_oversubscription_denied(self):
        self.assertEqual(self.check(count=4)["reason"],"invalid-multi-sample-selection-policy")

    def test_all_three_chunks_with_full_coverage(self):
        requests=[]
        replies=[]
        for j,idx in enumerate(mod.indices(self.seed,self.f.digest,3,3)):
            challenge=dict(self.f.challenge,nonce_hex=mod.nonce(self.seed,self.f.digest,j),
                           chunk_index=idx)
            requests.append(challenge)
            replies.append(self.f.answer(challenge,self.f.chunks[idx]))
        r=self.check(count=3,coverage=1000000,requests=requests,replies=replies)
        self.assertTrue(r["multi_sample_valid"])

    def test_separate_nonce_per_ordinal(self):
        self.assertNotEqual(self.requests[0]["nonce_hex"],self.requests[1]["nonce_hex"])


if __name__=="__main__":
    unittest.main()
