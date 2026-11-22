"""Signed organizational witness registry: quorum, rotations and revocations."""
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
    "witness_registry_fixture", ROOT / "tests" / "test_custody_ack_witness_quorum.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location(
    "witness_registry", ROOT / "tools" / "custody_witness_registry.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CustodyWitnessRegistryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.CustodyAckWitnessQuorumTests(
            methodName="test_two_signers_same_head_pass_pending")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(81,113)))  # TEST ONLY
        pub = self.issuer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer_id = hashlib.sha256(pub).hexdigest()
        self.issuer_roots = {self.issuer_id: pub}
        self.registry = self.make_registry()

    def make_registry(self, entries=None, revision=3, threshold=2):
        if entries is None:
            entries = [(self.f.f.key_id, "org-alpha", "active"),
                       (self.f.second_id, "org-beta", "active")]
        rows = [{"organization_id": org, "witness_key_id": key, "status":status}
                for key, org, status in sorted(entries)]
        body = {"schema_version": "0.1.0", "revision": revision,
                "minimum_organizations": threshold, "witnesses": rows}
        signature = self.issuer.sign(mod.DOMAIN + mod.canonical_registry(body))
        return {"registry": body, "issuer_key_id": self.issuer_id,
                "signature_b64":base64.b64encode(signature).decode()}

    def check(self, registry=None, envelopes=None, issuer_roots=None,
              revoked_issuers=None, witness_roots=None, revoked=None,
              revision=3, minimum=1, organizations=2):
        result = mod.verify(
            self.f.f.db, self.registry if registry is None else registry,
            [self.f.one,self.f.two] if envelopes is None else envelopes,
            self.issuer_roots if issuer_roots is None else issuer_roots,
            set() if revoked_issuers is None else revoked_issuers,
            self.f.roots if witness_roots is None else witness_roots,
            set() if revoked is None else revoked,
            revision, minimum, organizations)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_two_organizations_valid_pending_only(self):
        result = self.check()
        self.assertTrue(result["registry_quorum_valid"])
        self.assertEqual(result["organizations"],2)

    def test_independently_pinned_revision_denies_stale(self):
        self.assertEqual(self.check(revision=4)["reason"],"stale-witness-registry")

    def test_untrusted_issuer_denied(self):
        self.assertEqual(self.check(issuer_roots={})["reason"],"untrusted-registry-issuer")

    def test_revoked_issuer_denied(self):
        self.assertEqual(self.check(revoked_issuers={self.issuer_id})["reason"],"registry-issuer-revoked")

    def test_forged_registry_signature_denied(self):
        x=copy.deepcopy(self.registry)
        x["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(registry=x)["reason"],"invalid-registry-signature")

    def test_changed_organization_without_resigning_denied(self):
        x=copy.deepcopy(self.registry)
        x["registry"]["witnesses"][0]["organization_id"]="org-gamma"
        self.assertEqual(self.check(registry=x)["reason"],"invalid-registry-signature")

    def test_two_keys_one_organization_rejected(self):
        entries=[(self.f.f.key_id,"org-alpha","active"),
                 (self.f.second_id,"org-alpha","active")]
        with self.assertRaisesRegex(ValueError,"multiple-active-keys"):
            self.make_registry(entries)

    def test_repeated_key_for_multiple_organizations_rejected(self):
        entries=[(self.f.f.key_id,"org-alpha","active"),
                 (self.f.f.key_id,"org-beta","active")]
        with self.assertRaisesRegex(ValueError,"witness-key-reused"):
            self.make_registry(entries)

    def test_revocation_in_registry_denies_old_witness(self):
        third = Ed25519PrivateKey.from_private_bytes(bytes(range(101,133)))
        pub = third.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        new_id=hashlib.sha256(pub).hexdigest()
        entries=[(self.f.f.key_id,"org-alpha","revoked"),
                 (new_id,"org-alpha","active"),
                 (self.f.second_id,"org-beta","active")]
        registry=self.make_registry(entries,revision=4)
        self.assertEqual(self.check(registry=registry,revision=4)["reason"],
                         "witness-key-not-active-in-registry")

    def test_signed_rotation_new_key_can_qualify(self):
        third = Ed25519PrivateKey.from_private_bytes(bytes(range(101,133)))
        pub = third.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        new_id=hashlib.sha256(pub).hexdigest()
        entries=[(self.f.f.key_id,"org-alpha","revoked"),
                 (new_id,"org-alpha","active"),
                 (self.f.second_id,"org-beta","active")]
        registry=self.make_registry(entries,revision=4)
        body=copy.deepcopy(self.f.one["anchor"])
        sig=third.sign(mod.quorum.signed.DOMAIN + mod.quorum.signed.canonical_anchor(body))
        new_envelope={"anchor":body,"witness_key_id":new_id,
                      "signature_b64":base64.b64encode(sig).decode()}
        roots={**self.f.roots,new_id:pub}
        result=self.check(registry=registry,envelopes=[new_envelope,self.f.two],
                          witness_roots=roots,revision=4)
        self.assertTrue(result["registry_quorum_valid"])

    def test_revoked_external_witness_denied(self):
        self.assertEqual(self.check(revoked={self.f.second_id})["reason"],
                         "insufficient-eligible-organizations")

    def test_required_three_org_floor_denied(self):
        self.assertEqual(self.check(organizations=3)["reason"],
                         "insufficient-eligible-organizations")

    def test_extra_authority_field_denied(self):
        x=copy.deepcopy(self.registry)
        x["registry"]["authorization_granted"]=True
        self.assertEqual(self.check(registry=x)["reason"],"invalid-registry-schema")

    def test_bad_revocation_set_denied(self):
        self.assertEqual(self.check(revoked={"bad"})["reason"],"invalid-trusted-revocations")

    def test_boolean_minimum_revision_denied(self):
        self.assertEqual(self.check(revision=True)["reason"],"missing-trusted-registry-floor")

    def test_forged_issuer_id_denied(self):
        x=copy.deepcopy(self.registry)
        x["issuer_key_id"]="f"*64
        self.assertEqual(self.check(registry=x)["reason"],"untrusted-registry-issuer")

    def test_invalid_witness_signature_denied(self):
        bad=copy.deepcopy(self.f.two)
        bad["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(envelopes=[self.f.one,bad])["reason"],
                         "invalid-signed-ack-signature")

    def test_conflicting_signed_witness_denied(self):
        bad=self.f.make_second(head="f"*64)
        self.assertEqual(self.check(envelopes=[self.f.one,bad])["reason"],
                         "conflicting-witness-anchor")

    def test_registry_duplicate_organization_submission_denied(self):
        x=copy.deepcopy(self.f.one)
        self.assertEqual(self.check(envelopes=[self.f.one,x])["reason"],
                         "duplicate-witness-organization")

    def test_external_history_floor_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"],"stale-signed-ack-anchor")

    def test_missing_local_database_denied(self):
        self.f.f.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-ack-register")


if __name__=="__main__":
    unittest.main()
