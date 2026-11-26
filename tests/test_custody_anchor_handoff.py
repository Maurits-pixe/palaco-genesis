"""Offline custody-ledger checkpoint handoff and signed custodian acknowledgements."""
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
    "anchor_fixture", ROOT / "tests" / "test_signed_custody_ledger_anchor.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location(
    "custody_handoff", ROOT / "tools" / "custody_anchor_handoff.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CustodyAnchorHandoffTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.CustodyLedgerAnchorTests(methodName="test_valid_signed_chain_pending_only")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.receipts = Path(t.name) / "received.sqlite"
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(41,73)))  # TEST ONLY
        pub = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.cid = hashlib.sha256(pub).hexdigest()
        self.croots = {self.cid:pub}
        self.package_result = mod.prepare(self.f.db, self.f.envelope(), "custodian-a",
                                          self.f.roots, set(), 1)
        self.assertTrue(self.package_result["package_prepared"])
        self.package = self.package_result["package"]
        self.digest = self.package_result["package_sha256"]

    def ack(self, ident="a"*32, recipient="custodian-a", digest=None):
        body = {"schema_version":"0.1.0", "recipient_id":recipient,
                "package_sha256":self.digest if digest is None else digest,
                "receipt_id":ident, "disposition":mod.DISPOSITION}
        sig = self.signer.sign(mod.ACK_DOMAIN+mod.canonical_ack(body))
        return {"acknowledgement":body, "custodian_key_id":self.cid,
                "signature_b64":base64.b64encode(sig).decode()}

    def verify(self, ack=None, package=None, expected=None, recipient="custodian-a",
               roots=None, revoked=None, allowed=None, floor=1):
        result = mod.verify_ack(
            self.f.db, self.package if package is None else package,
            self.ack() if ack is None else ack, recipient,
            self.digest if expected is None else expected,
            self.f.roots, set(), floor,
            self.croots if roots is None else roots,
            set() if revoked is None else revoked,
            {self.cid} if allowed is None else allowed)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def record(self, ack=None):
        result = mod.register_ack(
            self.receipts, self.f.db, self.package, self.ack() if ack is None else ack,
            "custodian-a", self.digest, self.f.roots, set(), 1,
            self.croots, set(), {self.cid})
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        return result

    def test_verified_signed_receipt_pending_only(self):
        self.assertTrue(self.verify()["ack_valid"])

    def test_repeat_receipt_rejected(self):
        self.assertTrue(self.record()["recorded"])
        self.assertEqual(self.record()["reason"],"acknowledgement-replay")

    def test_new_receipt_same_package_rejected(self):
        self.record()
        self.assertEqual(self.record(self.ack("b"*32))["reason"],"duplicate-package-acknowledgement")

    def test_wrong_custodian_key_denied(self):
        self.assertEqual(self.verify(roots={})["reason"],"untrusted-custodian")

    def test_revoked_custodian_denied(self):
        self.assertEqual(self.verify(revoked={self.cid})["reason"],"custodian-revoked")

    def test_custodian_not_allowed_denied(self):
        self.assertEqual(self.verify(allowed=set())["reason"],"custodian-not-allowed")

    def test_invalid_signature_denied(self):
        changed=self.ack()
        changed["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.verify(ack=changed)["reason"],"invalid-ack-signature")

    def test_signature_mutation_denied(self):
        changed=self.ack()
        changed["acknowledgement"]["receipt_id"]="b"*32
        self.assertEqual(self.verify(ack=changed)["reason"],"invalid-ack-signature")

    def test_wrong_external_hash_denied(self):
        self.assertEqual(self.verify(expected="f"*64)["reason"],"package-hash-mismatch")

    def test_modified_package_denied(self):
        package=copy.deepcopy(self.package)
        package["recipient_id"]="custodian-b"
        self.assertEqual(self.verify(package=package)["reason"],"recipient-mismatch")

    def test_acknowledgement_wrong_recipient_denied(self):
        self.assertEqual(self.verify(ack=self.ack(recipient="other"))["reason"],"acknowledgement-binding-mismatch")

    def test_prohibited_approval_disposition_denied(self):
        changed=self.ack()
        changed["acknowledgement"]["disposition"]="approved"
        self.assertEqual(self.verify(ack=changed)["reason"],"invalid-acknowledgement-disposition")

    def test_external_floor_blocks_stale(self):
        self.assertEqual(self.verify(floor=2)["reason"],"stale-custody-anchor")

    def test_missing_ledger_denied(self):
        self.f.db.unlink()
        self.assertEqual(self.verify()["reason"],"missing-custody-ledger")

    def test_invalid_receipt_not_registered(self):
        changed=self.ack()
        changed["signature_b64"]="wrong"
        self.assertEqual(self.record(changed)["reason"],"invalid-ack-signature-format")
        self.assertFalse(self.receipts.exists())

    def test_preparation_invalid_recipient_fails(self):
        result=mod.prepare(self.f.db,self.f.envelope(),"../bad",self.f.roots,set(),1)
        self.assertFalse(result["package_prepared"])

    def test_deterministic_package_digest(self):
        another=mod.prepare(self.f.db,self.f.envelope(),"custodian-a",self.f.roots,set(),1)
        self.assertEqual(another["package_sha256"],self.digest)

    def test_receipt_register_must_differ_from_ledger(self):
        with self.assertRaises(ValueError):
            mod.register_ack(self.f.db,self.f.db,self.package,self.ack(),
                             "custodian-a",self.digest,self.f.roots,set(),1,
                             self.croots,set(),{self.cid})


if __name__=="__main__":
    unittest.main()
