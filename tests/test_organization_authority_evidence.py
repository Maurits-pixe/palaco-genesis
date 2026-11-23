"""Authorization boundary tests for organization assessor delegation evidence."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
_fixture_spec = importlib.util.spec_from_file_location(
    "authority_fixture", ROOT / "tests" / "test_organization_identity_evidence.py")
fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(fixture)
_spec = importlib.util.spec_from_file_location(
    "authority_evidence", ROOT / "tools" / "organization_authority_evidence.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class OrganizationAuthorityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.OrganizationIdentityEvidenceTests(
            methodName="test_valid_evidence_still_pending")
        self.f.setUp()
        self.delegator = Ed25519PrivateKey.from_private_bytes(bytes(range(91,123)))  # TEST ONLY
        pub = self.delegator.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.did = hashlib.sha256(pub).hexdigest()
        self.roots = {self.did: pub}
        self.delegation = self.make_delegation()

    def make_delegation(self, updates=None):
        body = {"schema_version": "0.1.0", "revision": 5,
                "organization_id": "org-alpha", "assessor_key_id": self.f.assessor_id,
                "registry_revision": 2,
                "registry_envelope_sha256": mod.identity.succession.digest(self.f.f.snapshots[-1]),
                "identity_envelope_sha256": mod.digest_evidence(self.f.envelope),
                "scope": mod.SCOPE}
        body.update(updates or {})
        signature = self.delegator.sign(mod.DOMAIN + mod.canonical_delegation(body))
        return {"delegation": body, "delegator_key_id": self.did,
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, delegation=None, identity=None, roots=None, allowed=None,
              revoked=None, assessor_revoked=None, floor=5, history_floor=2,
              history_head=None):
        result = mod.verify(
            self.f.f.snapshots, self.f.f.records,
            self.f.envelope if identity is None else identity,
            self.delegation if delegation is None else delegation,
            self.f.f.roots, set(), self.f.roots,
            set() if assessor_revoked is None else assessor_revoked,
            {self.f.assessor_id}, self.roots if roots is None else roots,
            set() if revoked is None else revoked,
            {self.did} if allowed is None else allowed,
            mod.identity.succession.digest(self.f.f.snapshots[0]),
            mod.identity.succession.record_digest(self.f.f.records[-1])
              if history_head is None else history_head,
            history_floor, floor)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_delegation_is_pending_only(self):
        self.assertTrue(self.check()["delegation_valid"])

    def test_revoked_delegator_denied(self):
        self.assertEqual(self.check(revoked={self.did})["reason"], "delegator-revoked")

    def test_untrusted_delegator_denied(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-delegator")

    def test_unallowed_delegator_denied(self):
        self.assertEqual(self.check(allowed=set())["reason"], "delegator-not-allowed")

    def test_stale_revision_denied(self):
        self.assertEqual(self.check(floor=6)["reason"], "stale-delegation-revision")

    def test_boolean_revision_denied(self):
        invalid = copy.deepcopy(self.delegation)
        invalid["delegation"]["revision"] = True
        self.assertEqual(self.check(delegation=invalid)["reason"], "invalid-delegation-revision")

    def test_binding_to_wrong_organization_denied(self):
        invalid = self.make_delegation({"organization_id": "org-beta"})
        self.assertEqual(self.check(delegation=invalid)["reason"], "delegation-binding-mismatch")

    def test_binding_to_wrong_assessor_denied(self):
        invalid = self.make_delegation({"assessor_key_id": "f"*64})
        self.assertEqual(self.check(delegation=invalid)["reason"], "delegation-binding-mismatch")

    def test_binding_to_old_register_revision_denied(self):
        invalid = self.make_delegation({"registry_revision": 1})
        self.assertEqual(self.check(delegation=invalid)["reason"], "delegation-binding-mismatch")

    def test_binding_to_wrong_evidence_hash_denied(self):
        invalid = self.make_delegation({"identity_envelope_sha256": "f"*64})
        self.assertEqual(self.check(delegation=invalid)["reason"], "delegation-binding-mismatch")

    def test_bad_signature_denied(self):
        invalid = copy.deepcopy(self.delegation)
        invalid["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(delegation=invalid)["reason"], "invalid-delegation-signature")

    def test_signature_mutation_denied(self):
        invalid = copy.deepcopy(self.delegation)
        invalid["delegation"]["revision"] = 6
        self.assertEqual(self.check(delegation=invalid)["reason"], "invalid-delegation-signature")

    def test_unsigned_authority_escalation_denied(self):
        invalid = copy.deepcopy(self.delegation)
        invalid["delegation"]["release_authorized"] = True
        self.assertEqual(self.check(delegation=invalid)["reason"], "invalid-delegation-schema")

    def test_stronger_scope_forbidden(self):
        invalid = copy.deepcopy(self.delegation)
        invalid["delegation"]["scope"] = "deploy-and-release"
        self.assertEqual(self.check(delegation=invalid)["reason"], "invalid-delegation-scope")

    def test_revoked_assessor_denied(self):
        self.assertEqual(self.check(assessor_revoked={self.f.assessor_id})["reason"], "assessor-revoked")

    def test_tampered_identity_denied(self):
        invalid = copy.deepcopy(self.f.envelope)
        invalid["evidence"]["evidence_sha256"] = "f"*64
        self.assertEqual(self.check(identity=invalid)["reason"], "invalid-assessor-signature")

    def test_wrong_historical_pin_denied(self):
        self.assertEqual(self.check(history_head="f"*64)["reason"], "registry-history-head-mismatch")

    def test_history_rollback_denied(self):
        self.assertEqual(self.check(history_floor=3)["reason"], "registry-history-rollback")

    def test_missing_delegator_policy_denied(self):
        self.assertEqual(self.check(allowed=None, roots={})["reason"], "untrusted-delegator")

    def test_signature_format_denied(self):
        invalid = copy.deepcopy(self.delegation)
        invalid["signature_b64"] = "not-base64!"
        self.assertEqual(self.check(delegation=invalid)["reason"], "invalid-delegation-signature-format")


if __name__ == "__main__":
    unittest.main()
