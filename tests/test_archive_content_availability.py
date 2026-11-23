"""Offline independently pinned archive-content sampling negative regressions."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("archive_samples",ROOT/"tools"/"archive_content_availability.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ArchiveContentAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.from_private_bytes(bytes(range(22,54))) # TEST ONLY
        pub=self.key.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.kid=hashlib.sha256(pub).hexdigest()
        self.roots={self.kid:pub}
        self.chunks=[b"abcd",b"efgh",b"ij"]
        self.manifest={"schema_version":"0.1.0","archive_head_sha256":"a"*64,
                       "chunk_size":4,"total_bytes":10,
                       "chunk_sha256":[hashlib.sha256(c).hexdigest() for c in self.chunks]}
        self.digest=mod.manifest_digest(self.manifest)
        self.challenge={"schema_version":"0.1.0","requester_id":"audit-requester",
                        "nonce_hex":"b"*64,"manifest_sha256":self.digest,
                        "chunk_index":2,"issued_epoch":100,"expires_epoch":200}
        self.response=self.answer(self.challenge,self.chunks[2])

    def answer(self,challenge,chunk):
        reply={"challenge":copy.deepcopy(challenge),"custodian_key_id":self.kid,
               "chunk_b64":base64.b64encode(chunk).decode(),
               "signature_b64":""}
        reply["signature_b64"]=base64.b64encode(
            self.key.sign(mod.DOMAIN+mod.canonical_reply(reply))).decode()
        return reply

    def check(self,manifest=None,pin=None,archive=None,challenge=None,response=None,
              requester="audit-requester",nonce=None,now=150,used=None,
              roots=None,allowed=None,revoked=None):
        result=mod.verify(
            self.manifest if manifest is None else manifest,
            self.digest if pin is None else pin,
            "a"*64 if archive is None else archive,
            self.challenge if challenge is None else challenge,
            self.response if response is None else response,
            requester,"b"*64 if nonce is None else nonce,now,
            set() if used is None else used,self.roots if roots is None else roots,
            {self.kid} if allowed is None else allowed,
            set() if revoked is None else revoked)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_valid_last_chunk_pending_only(self):
        self.assertTrue(self.check()["content_sample_valid"])

    def test_valid_full_chunk_pending_only(self):
        c=dict(self.challenge,chunk_index=1)
        self.assertTrue(self.check(challenge=c,response=self.answer(c,self.chunks[1]))["content_sample_valid"])

    def test_wrong_manifest_pin(self):
        self.assertEqual(self.check(pin="f"*64)["reason"],"content-manifest-pin-mismatch")

    def test_wrong_archive_head(self):
        self.assertEqual(self.check(archive="f"*64)["reason"],"content-manifest-pin-mismatch")

    def test_wrong_nonce(self):
        self.assertEqual(self.check(nonce="f"*64)["reason"],"content-challenge-binding-mismatch")

    def test_replayed_nonce(self):
        self.assertEqual(self.check(used={"b"*64})["reason"],"content-challenge-replay")

    def test_future_challenge(self):
        self.assertEqual(self.check(now=99)["reason"],"content-challenge-expired-or-future")

    def test_expired_challenge(self):
        self.assertEqual(self.check(now=201)["reason"],"content-challenge-expired-or-future")

    def test_boolean_trusted_clock(self):
        self.assertEqual(self.check(now=True)["reason"],"missing-independent-content-policy")

    def test_wrong_requester(self):
        self.assertEqual(self.check(requester="other")["reason"],"content-challenge-binding-mismatch")

    def test_changed_response_challenge(self):
        r=copy.deepcopy(self.response)
        r["challenge"]["chunk_index"]=1
        self.assertEqual(self.check(response=r)["reason"],"content-response-challenge-mismatch")

    def test_wrong_chunk_content_signed(self):
        self.assertEqual(self.check(response=self.answer(self.challenge,b"xx"))["reason"],
                         "content-chunk-length-mismatch")

    def test_wrong_chunk_hash_signed(self):
        self.assertEqual(self.check(response=self.answer(self.challenge,b"zz"))["reason"],
                         "content-chunk-hash-mismatch")

    def test_unknown_chunk_index(self):
        c=dict(self.challenge,chunk_index=4)
        self.assertEqual(self.check(challenge=c,response=self.answer(c,b""))["reason"],
                         "content-chunk-out-of-range")

    def test_manifest_tampering(self):
        m=copy.deepcopy(self.manifest)
        m["chunk_sha256"][2]="f"*64
        self.assertEqual(self.check(manifest=m)["reason"],"content-manifest-pin-mismatch")

    def test_manifest_extra_authority_field(self):
        m=dict(self.manifest,authorization_granted=True)
        self.assertEqual(self.check(manifest=m)["reason"],"invalid-content-manifest-schema")

    def test_manifest_boolean_size(self):
        m=dict(self.manifest,chunk_size=True)
        self.assertEqual(self.check(manifest=m)["reason"],"invalid-content-chunk-size")

    def test_signature_corruption(self):
        r=copy.deepcopy(self.response)
        r["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(response=r)["reason"],"invalid-content-signature")

    def test_signature_encoding(self):
        r=copy.deepcopy(self.response)
        r["signature_b64"]="!"
        self.assertEqual(self.check(response=r)["reason"],"invalid-content-signature-format")

    def test_chunk_base64_invalid(self):
        r=copy.deepcopy(self.response)
        r["chunk_b64"]="!"
        self.assertEqual(self.check(response=r)["reason"],"invalid-content-chunk-encoding")

    def test_revoked_custodian(self):
        self.assertEqual(self.check(revoked={self.kid})["reason"],"content-custodian-revoked")

    def test_untrusted_custodian(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-content-custodian")

    def test_not_allowlisted(self):
        self.assertEqual(self.check(allowed=set())["reason"],"content-custodian-not-allowed")

    def test_extra_permission_in_response(self):
        r=dict(self.response,restore_allowed=True)
        self.assertEqual(self.check(response=r)["reason"],"invalid-content-reply-schema")

    def test_wrong_signed_manifest_binding(self):
        c=dict(self.challenge,manifest_sha256="f"*64)
        self.assertEqual(self.check(challenge=c,response=self.answer(c,b"ij"))["reason"],
                         "content-challenge-binding-mismatch")


if __name__=="__main__":
    unittest.main()
