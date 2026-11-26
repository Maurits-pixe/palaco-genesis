"""Multi-witness custody acknowledgement quorum adversarial regressions."""
import base64
import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
fixture_spec = importlib.util.spec_from_file_location(
    "ack_anchor_fixture", ROOT / "tests" / "test_signed_custody_ack_anchor.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
module_spec = importlib.util.spec_from_file_location(
    "ack_quorum", ROOT / "tools" / "custody_ack_witness_quorum.py")
mod = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(mod)


class CustodyAckWitnessQuorumTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.SignedCustodyAckAnchorTests(
            methodName="test_valid_signed_anchor_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.second = Ed25519PrivateKey.from_private_bytes(bytes(range(61, 93)))  # TEST ONLY
        pub = self.second.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.second_id = hashlib.sha256(pub).hexdigest()
        self.roots = {**self.f.roots, self.second_id: pub}
        self.allowed = {self.f.key_id, self.second_id}
        self.one = self.f.envelope()
        self.two = self.make_second()

    def make_second(self, entries=1, head=None):
        body = {"schema_version": "0.1.0", "entries": entries,
                "ack_head_sha256": self.f.head if head is None else head}
        sig = self.second.sign(mod.signed.DOMAIN +
                               mod.signed.canonical_anchor(body))
        return {"anchor":body, "witness_key_id":self.second_id,
                "signature_b64":base64.b64encode(sig).decode()}

    def check(self, envelopes=None, roots=None, allowed=None,
              revoked=None, threshold=2, minimum=1):
        result = mod.verify(self.f.db, [self.one,self.two] if envelopes is None else envelopes,
                            self.roots if roots is None else roots,
                            self.allowed if allowed is None else allowed,
                            set() if revoked is None else revoked, threshold, minimum)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_two_signers_same_head_pass_pending(self):
        self.assertTrue(self.check()["quorum_valid"])
        self.assertEqual(self.check()["witnesses"],2)

    def test_order_independent(self):
        self.assertTrue(self.check([self.two,self.one])["quorum_valid"])

    def test_one_witness_insufficient(self):
        self.assertEqual(self.check([self.one])["reason"],
                         "insufficient-or-excess-witness-statements")

    def test_duplicate_witness_denied(self):
        self.assertEqual(self.check([self.one,self.one])["reason"],"duplicate-witness")

    def test_untrusted_second_root_denied(self):
        self.assertEqual(self.check(roots=self.f.roots)["reason"],"untrusted-ack-witness")

    def test_revoked_second_denied(self):
        self.assertEqual(self.check(revoked={self.second_id})["reason"],
                         "insufficient-eligible-witness-roots")

    def test_unallowed_second_denied(self):
        self.assertEqual(self.check(allowed={self.f.key_id})["reason"],
                         "insufficient-eligible-witness-roots")

    def test_wrong_second_signature_denied(self):
        bad = copy.deepcopy(self.two)
        bad["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check([self.one,bad])["reason"],
                         "invalid-signed-ack-signature")

    def test_forged_second_head_denied(self):
        bad = copy.deepcopy(self.two)
        bad["anchor"]["ack_head_sha256"] = "f"*64
        self.assertEqual(self.check([self.one,bad])["reason"],
                         "invalid-signed-ack-signature")

    def test_signed_conflicting_head_denied(self):
        divergent=self.make_second(head="f"*64)
        self.assertEqual(self.check([self.one,divergent])["reason"],
                         "conflicting-witness-anchor")

    def test_signed_conflicting_count_denied(self):
        divergent=self.make_second(entries=2)
        self.assertEqual(self.check([self.one,divergent])["reason"],
                         "conflicting-witness-anchor")

    def test_stale_floor_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"],
                         "stale-signed-ack-anchor")

    def test_boolean_threshold_denied(self):
        self.assertEqual(self.check(threshold=True)["reason"],
                         "invalid-quorum-or-history-floor")

    def test_threshold_above_roster_denied(self):
        self.assertEqual(self.check(threshold=3)["reason"],
                         "insufficient-eligible-witness-roots")

    def test_extra_permission_field_denied(self):
        bad=copy.deepcopy(self.two)
        bad["authorize"]=True
        self.assertEqual(self.check([self.one,bad])["reason"],"invalid-witness-envelope")

    def test_unknown_third_signer_denied(self):
        other=copy.deepcopy(self.two)
        other["witness_key_id"]="a"*64
        self.assertEqual(self.check([self.one,other])["reason"],"witness-not-allowed")

    def test_altered_local_chain_denied(self):
        old=[self.one,self.two]
        self.f.add_event("2"*32,"e"*64)
        self.assertEqual(self.check(old)["reason"],"conflicting-witness-anchor")

    def test_missing_database_denied(self):
        self.f.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-ack-register")


if __name__=="__main__":
    unittest.main()
