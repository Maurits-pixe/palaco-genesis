"""Signed assessor delegation succession and irrevocable revocation checks."""
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
    "org_delegation_fixture", ROOT / "tests" / "test_organization_authority_evidence.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location(
    "org_delegation_history", ROOT / "tools" / "organization_delegation_history.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class OrganizationDelegationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.OrganizationAuthorityEvidenceTests(
            methodName="test_valid_delegation_is_pending_only")
        self.f.setUp()
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(111, 143)))  # TEST ONLY
        pub = self.issuer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.issuer_id = hashlib.sha256(pub).hexdigest()
        self.roots = {self.issuer_id: pub}
        self.records = [self.event(1, "active", mod.GENESIS)]

    def event(self, revision, state, previous, overrides=None):
        body = {"schema_version": "0.1.0", "revision": revision,
                "delegation_sha256": mod.delegation_digest(self.f.delegation),
                "organization_id": "org-alpha",
                "assessor_key_id": self.f.f.assessor_id, "status": state,
                "previous_record_sha256": previous}
        body.update(overrides or {})
        signature = self.issuer.sign(mod.DOMAIN + mod.canonical(body))
        return {"status": body, "issuer_key_id": self.issuer_id,
                "signature_b64": base64.b64encode(signature).decode()}

    def append(self, state="revoked", revision=2):
        previous = mod.record_digest(self.records[-1])
        record = self.event(revision, state, previous)
        self.records.append(record)
        return record

    def check(self, records=None, roots=None, revoked=None, allowed=None,
              minimum=1, genesis=None, head=None, signed_delegation=None):
        rr = self.records if records is None else records
        result = mod.verify(
            self.f.f.f.snapshots, self.f.f.f.records,
            self.f.f.envelope,
            self.f.delegation if signed_delegation is None else signed_delegation,
            self.f.f.f.roots, set(),
            self.f.f.roots, set(), {self.f.f.assessor_id},
            self.f.roots, set(), {self.f.did},
            self.roots if roots is None else roots,
            set() if revoked is None else revoked,
            {self.issuer_id} if allowed is None else allowed,
            mod.authority.identity.succession.digest(self.f.f.f.snapshots[0]),
            mod.authority.identity.succession.record_digest(self.f.f.f.records[-1]),
            2, 5,
            mod.record_digest(self.records[0]) if genesis is None else genesis,
            mod.record_digest(rr[-1]) if (head is None and rr) else (mod.GENESIS if head is None else head),
            minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_activation_pending_only(self):
        self.assertTrue(self.check()["delegation_history_valid"])

    def test_revocation_quarantines(self):
        self.append()
        self.assertEqual(self.check()["reason"], "delegation-revoked")

    def test_revoked_delegation_cannot_reactivate(self):
        self.append()
        self.append("active", 3)
        self.assertEqual(self.check()["reason"], "revoked-delegation-resurrected")

    def test_duplicate_revocation_quarantines(self):
        self.append()
        self.append("revoked", 3)
        self.assertEqual(self.check()["reason"], "duplicate-revocation")

    def test_missing_intermediate_revision_denied(self):
        self.append("revoked", 3)
        self.assertEqual(self.check()["reason"], "status-revision-gap")

    def test_rollback_floor_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"], "status-history-rollback")

    def test_wrong_independent_head_denied(self):
        self.assertEqual(self.check(head="f"*64)["reason"], "status-history-head-mismatch")

    def test_wrong_independent_genesis_denied(self):
        self.assertEqual(self.check(genesis="f"*64)["reason"], "untrusted-status-genesis")

    def test_revoked_status_issuer_denied(self):
        self.assertEqual(self.check(revoked={self.issuer_id})["reason"], "status-issuer-revoked")

    def test_untrusted_status_issuer_denied(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-status-issuer")

    def test_status_issuer_not_allowed_denied(self):
        self.assertEqual(self.check(allowed=set())["reason"], "status-issuer-not-allowed")

    def test_tampered_status_signature_denied(self):
        altered = copy.deepcopy(self.records)
        altered[0]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(records=altered)["reason"], "untrusted-status-genesis")

    def test_signed_status_binding_wrong_delegation_denied(self):
        altered = [self.event(1, "active", mod.GENESIS,
                              {"delegation_sha256": "f"*64})]
        self.assertEqual(self.check(records=altered)["reason"],
                         "status-delegation-binding-mismatch")

    def test_signature_invalid_with_external_genesis_aligned(self):
        altered = copy.deepcopy(self.records)
        altered[0]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(records=altered, genesis=mod.record_digest(altered[0]))["reason"],
                         "invalid-status-signature")

    def test_invalid_signature_encoding_denied(self):
        altered = copy.deepcopy(self.records)
        altered[0]["signature_b64"] = "!"
        self.assertEqual(self.check(records=altered, genesis=mod.record_digest(altered[0]))["reason"],
                         "invalid-status-signature-format")

    def test_extra_authority_field_denied(self):
        altered = copy.deepcopy(self.records)
        altered[0]["status"]["release_approved"] = True
        self.assertEqual(self.check(records=altered)["reason"],
                         "invalid-delegation-status-schema")

    def test_boolean_revision_denied(self):
        altered = copy.deepcopy(self.records)
        altered[0]["status"]["revision"] = True
        self.assertEqual(self.check(records=altered)["reason"],
                         "invalid-status-revision")

    def test_different_signed_delegation_fails_prior_verification(self):
        altered = copy.deepcopy(self.f.delegation)
        altered["delegation"]["revision"] = 6
        self.assertEqual(self.check(signed_delegation=altered)["reason"],
                         "invalid-delegation-signature")

    def test_empty_history_denied(self):
        result = mod.verify(
            self.f.f.f.snapshots, self.f.f.f.records, self.f.f.envelope,
            self.f.delegation, self.f.f.f.roots, set(), self.f.f.roots, set(),
            {self.f.f.assessor_id}, self.f.roots, set(), {self.f.did},
            self.roots, set(), {self.issuer_id},
            mod.authority.identity.succession.digest(self.f.f.f.snapshots[0]),
            mod.authority.identity.succession.record_digest(self.f.f.f.records[-1]),
            2, 5, mod.record_digest(self.records[0]),
            mod.record_digest(self.records[0]), 1, [])
        self.assertFalse(result["delegation_history_valid"])


if __name__ == "__main__":
    unittest.main()
