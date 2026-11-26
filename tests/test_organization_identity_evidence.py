"""Organization identity assessor evidence is always HOLD-only."""
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
    "history_fixture",ROOT/"tests"/"test_witness_registry_succession.py")
fixture=importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location(
    "org_identity_evidence",ROOT/"tools"/"organization_identity_evidence.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class OrganizationIdentityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.WitnessRegistrySuccessionTests(
            methodName="test_valid_signed_rotation_pending_only")
        self.f.setUp()
        self.assessor=Ed25519PrivateKey.from_private_bytes(bytes(range(71,103))) # TEST ONLY
        pub=self.assessor.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.assessor_id=hashlib.sha256(pub).hexdigest()
        self.roots={self.assessor_id:pub}
        self.envelope=self.make_evidence()

    def make_evidence(self,updates=None):
        latest=self.f.snapshots[-1]
        body={"schema_version":"0.1.0","organization_id":"org-alpha",
              "witness_key_id":self.f.c,"registry_revision":2,
              "registry_envelope_sha256":mod.succession.digest(latest),
              "evidence_sha256":"d"*64,"assessment":mod.ASSESSMENT}
        body.update(updates or {})
        signature=self.assessor.sign(mod.DOMAIN+mod.canonical(body))
        return {"evidence":body,"assessor_key_id":self.assessor_id,
                "signature_b64":base64.b64encode(signature).decode()}

    def check(self,envelope=None,roster=None,revoked=None,roots=None,
              head=None,floor=2,issuer_revoked=None):
        result=mod.verify(
            self.f.snapshots,self.f.records,
            self.envelope if envelope is None else envelope,self.f.roots,
            set() if issuer_revoked is None else issuer_revoked,
            self.roots if roots is None else roots,
            set() if revoked is None else revoked,
            {self.assessor_id} if roster is None else roster,
            mod.succession.digest(self.f.snapshots[0]),
            mod.succession.record_digest(self.f.records[-1]) if head is None else head,
            floor)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_evidence_still_pending(self):
        self.assertTrue(self.check(self.envelope)["identity_evidence_valid"])

    def test_revoked_assessor_denied(self):
        self.assertEqual(self.check(self.envelope,revoked={self.assessor_id})["reason"],"assessor-revoked")

    def test_untrusted_assessor_denied(self):
        self.assertEqual(self.check(self.envelope,roots={})["reason"],"untrusted-assessor")

    def test_assessor_not_allowed_denied(self):
        self.assertEqual(self.check(self.envelope,roster=set())["reason"],"assessor-not-allowed")

    def test_stale_revision_denied(self):
        self.assertEqual(self.check(self.make_evidence({"registry_revision":1}))["reason"],
                         "stale-identity-evidence-binding")

    def test_old_key_denied(self):
        self.assertEqual(self.check(self.make_evidence({"witness_key_id":self.f.a}))["reason"],
                         "identity-evidence-witness-mismatch")

    def test_wrong_organization_denied(self):
        self.assertEqual(self.check(self.make_evidence({"organization_id":"org-gamma"}))["reason"],
                         "identity-evidence-witness-mismatch")

    def test_changed_evidence_digest_denied(self):
        e=copy.deepcopy(self.envelope)
        e["evidence"]["evidence_sha256"]="f"*64
        self.assertEqual(self.check(e)["reason"],"invalid-assessor-signature")

    def test_changed_signed_assessment_denied(self):
        e=copy.deepcopy(self.envelope)
        e["evidence"]["assessment"]="legal-identity-approved"
        self.assertEqual(self.check(e)["reason"],"invalid-identity-assessment")

    def test_extra_authority_denied(self):
        e=copy.deepcopy(self.envelope)
        e["evidence"]["authorization_granted"]=True
        self.assertEqual(self.check(e)["reason"],"invalid-identity-evidence-schema")

    def test_wrong_trusted_history_pin_denied(self):
        self.assertEqual(self.check(self.envelope,head="f"*64)["reason"],
                         "registry-history-head-mismatch")

    def test_invalid_history_floor_denied(self):
        self.assertEqual(self.check(self.envelope,floor=3)["reason"],
                         "registry-history-rollback")

    def test_revoked_governance_issuer_denied(self):
        self.assertEqual(self.check(self.envelope,issuer_revoked={self.f.iid})["reason"],
                         "registry-issuer-revoked")

    def test_bad_assessor_signature_denied(self):
        e=copy.deepcopy(self.envelope)
        e["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(e)["reason"],"invalid-assessor-signature")


if __name__=="__main__":
    unittest.main()
