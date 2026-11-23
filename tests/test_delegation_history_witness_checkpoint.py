"""Cross-check externally pinned delegation histories with two witness organizations."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
fixture_spec = importlib.util.spec_from_file_location(
    "delegation_fixture_for_quorum", ROOT / "tests" / "test_organization_delegation_history.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location(
    "delegation_quorum", ROOT / "tools" / "delegation_history_witness_checkpoint.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DelegationWitnessCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.OrganizationDelegationHistoryTests(
            methodName="test_valid_activation_pending_only")
        self.f.setUp()
        self.signers = [
            Ed25519PrivateKey.from_private_bytes(bytes(range(10, 42))),
            Ed25519PrivateKey.from_private_bytes(bytes(range(20, 52)))
        ]  # TEST ONLY: NOT production or issued keys
        self.roots = {}
        self.organizations = {}
        self.ids = []
        for signer, org in zip(self.signers, ("witness-alpha", "witness-beta")):
            pub = signer.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            key = hashlib.sha256(pub).hexdigest()
            self.ids.append(key)
            self.roots[key] = pub
            self.organizations[key] = org
        self.inputs = self.history_inputs()
        self.claims = [self.claim(0), self.claim(1)]

    def history_inputs(self):
        succession = self.f.f.f.f
        assessor = self.f.f.f
        authority = self.f.f
        return {
            "snapshots": succession.snapshots,
            "registry_records": succession.records,
            "signed_identity": assessor.envelope,
            "signed_delegation": authority.delegation,
            "registry_issuer_roots": succession.roots,
            "revoked_registry_issuers": set(),
            "assessor_roots": assessor.roots,
            "revoked_assessors": set(),
            "allowed_assessors": {assessor.assessor_id},
            "delegator_roots": authority.roots,
            "revoked_delegators": set(),
            "allowed_delegators": {authority.did},
            "status_issuer_roots": self.f.roots,
            "revoked_status_issuers": set(),
            "allowed_status_issuers": {self.f.issuer_id},
            "trusted_registry_genesis": mod.history.authority.identity.succession.digest(
                succession.snapshots[0]),
            "trusted_registry_head": mod.history.authority.identity.succession.record_digest(
                succession.records[-1]),
            "minimum_registry_revision": 2,
            "minimum_delegation_revision": 5,
            "trusted_status_genesis": mod.history.record_digest(self.f.records[0]),
            "trusted_status_head": mod.history.record_digest(self.f.records[-1]),
            "minimum_status_revision": 1
        }

    def body(self):
        authority = self.f.f
        return {
            "schema_version": "0.1.0",
            "organization_id": "org-alpha",
            "assessor_key_id": authority.f.assessor_id,
            "delegation_sha256": mod.history.delegation_digest(authority.delegation),
            "status_genesis_sha256": self.inputs["trusted_status_genesis"],
            "status_head_sha256": self.inputs["trusted_status_head"],
            "status_revision": 1
        }

    def claim(self, signer_index, overrides=None):
        body = self.body()
        body.update(overrides or {})
        signature = self.signers[signer_index].sign(mod.DOMAIN + mod.canonical(body))
        return {"checkpoint": body, "witness_key_id": self.ids[signer_index],
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, claims=None, inputs=None, roots=None, orgs=None,
              revoked=None, minimum=2):
        result = mod.verify(
            self.inputs if inputs is None else inputs,
            self.f.records,
            self.claims if claims is None else claims,
            self.roots if roots is None else roots,
            self.organizations if orgs is None else orgs,
            set() if revoked is None else revoked, minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_two_witnesses_pending_only(self):
        r = self.check()
        self.assertTrue(r["checkpoint_quorum_valid"])
        self.assertEqual(r["organizations"], 2)

    def test_reversed_order_valid(self):
        self.assertTrue(self.check(list(reversed(self.claims)))["checkpoint_quorum_valid"])

    def test_single_witness_denied(self):
        self.assertEqual(self.check([self.claims[0]])["reason"],
                         "invalid-witness-submission-count")

    def test_duplicate_witness_denied(self):
        self.assertEqual(self.check([self.claims[0], self.claims[0]])["reason"],
                         "duplicate-delegation-witness")

    def test_same_organization_two_keys_denied(self):
        orgs = {key: "witness-alpha" for key in self.ids}
        self.assertEqual(self.check(orgs=orgs)["reason"],
                         "insufficient-eligible-organizations")

    def test_revoked_second_witness_denied(self):
        self.assertEqual(self.check(revoked={self.ids[1]})["reason"],
                         "insufficient-eligible-organizations")

    def test_untrusted_second_witness_denied(self):
        roots = {self.ids[0]: self.roots[self.ids[0]]}
        self.assertEqual(self.check(roots=roots)["reason"],
                         "untrusted-delegation-witness")

    def test_invalid_second_signature_denied(self):
        claims = copy.deepcopy(self.claims)
        claims[1]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(claims)["reason"],
                         "invalid-delegation-witness-signature")

    def test_bad_base64_denied(self):
        claims = copy.deepcopy(self.claims)
        claims[1]["signature_b64"] = "!"
        self.assertEqual(self.check(claims)["reason"],
                         "invalid-witness-signature-format")

    def test_signed_conflicting_head_denied(self):
        conflict = self.claim(1, {"status_head_sha256": "f"*64})
        self.assertEqual(self.check([self.claims[0], conflict])["reason"],
                         "conflicting-delegation-checkpoint")

    def test_signed_conflicting_revision_denied(self):
        conflict = self.claim(1, {"status_revision": 2})
        self.assertEqual(self.check([self.claims[0], conflict])["reason"],
                         "conflicting-delegation-checkpoint")

    def test_mutated_checkpoint_signature_denied(self):
        claims = copy.deepcopy(self.claims)
        claims[1]["checkpoint"]["status_revision"] = 2
        self.assertEqual(self.check(claims)["reason"],
                         "conflicting-delegation-checkpoint")

    def test_added_permission_field_denied(self):
        claims = copy.deepcopy(self.claims)
        claims[0]["checkpoint"]["release_approved"] = True
        self.assertEqual(self.check(claims)["reason"],
                         "invalid-delegation-checkpoint-schema")

    def test_boolean_revision_denied(self):
        claims = copy.deepcopy(self.claims)
        claims[0]["checkpoint"]["status_revision"] = True
        self.assertEqual(self.check(claims)["reason"],
                         "invalid-checkpoint-revision")

    def test_wrong_external_head_denied(self):
        data = dict(self.inputs)
        data["trusted_status_head"] = "f"*64
        self.assertEqual(self.check(inputs=data)["reason"],
                         "status-history-head-mismatch")

    def test_external_history_floor_denied(self):
        data = dict(self.inputs)
        data["minimum_status_revision"] = 2
        self.assertEqual(self.check(inputs=data)["reason"],
                         "status-history-rollback")

    def test_revoked_delegation_history_denied(self):
        self.f.append()
        data = self.history_inputs()
        self.assertEqual(self.check(inputs=data)["reason"], "delegation-revoked")

    def test_unknown_witness_policy_rejected(self):
        policy = dict(self.organizations)
        policy["bad-key"] = "witness-gamma"
        self.assertEqual(self.check(orgs=policy)["reason"],
                         "invalid-witness-organization-policy")

    def test_missing_external_history_parameters_denied(self):
        data = dict(self.inputs)
        del data["trusted_status_genesis"]
        self.assertEqual(self.check(inputs=data)["reason"],
                         "missing-trusted-history-inputs")

    def test_witness_key_role_collision_denied(self):
        roots = dict(self.roots)
        key = self.f.issuer_id
        roots[key] = self.f.roots[key]
        policy = {self.ids[0]: "witness-alpha", key: "witness-beta"}
        rec = self.claims[0]
        bad = copy.deepcopy(self.claims[1])
        bad["witness_key_id"] = key
        self.assertEqual(self.check([rec, bad], roots=roots, orgs=policy)["reason"],
                         "witness-role-collision")


if __name__ == "__main__":
    unittest.main()
