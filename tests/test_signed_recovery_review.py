"""Signed recovery decision stays advisory even with eligible reviewer."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("signed_review", ROOT / "tools" / "signed_recovery_review.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedRecoveryReviewTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))
        public = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        root = self.issuer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(public).hexdigest()
        self.issuer_id = hashlib.sha256(root).hexdigest()
        self.keys = {self.key_id: public}
        self.roots = {self.issuer_id: root}
        self.review = {"reviewer_id": "reviewer-a", "decision": "request-review",
                       "reason": "Further security inspection required",
                       "reviewed_at_utc": "2026-11-22T05:00:00Z"}
        self.dossier = {
            "schema_version": "0.1.0", "record_type": "local-recovery-review-dossier",
            "assessment_state": "pending-review", "assessment_reason": "local-consistency-only",
            "witness_sha256": "1" * 64, "issuer_key_id": self.issuer_id,
            "witness_sequence": 1, "witness_head": "2" * 64,
            "manual_review": dict(self.review),
            "required_follow_up": "independent-security-review",
        }
        self.digest = hashlib.sha256(
            b"PALACO-RECOVERY-DOSSIER-V1\x00" + mod.dossiers.canonical(self.dossier)
        ).hexdigest()
        self.registry = self.make_registry()
        self.at = "2026-11-22T05:00:00Z"

    def make_registry(self, revoked=False):
        body = {"schema_version": "0.1.0", "revision": 7, "reviewers": [{
            "reviewer_id": "reviewer-a", "key_fingerprint": self.key_id,
            "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
            "revoked": revoked,
        }]}
        sig = self.issuer.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00" + mod.reviewers.canonical(body))
        return {"snapshot": body, "issuer_key_id": self.issuer_id,
                "issuer_signature_b64": base64.b64encode(sig).decode()}

    def envelope(self, declaration=None):
        body = {"schema_version": "0.1.0", "dossier_sha256": self.digest, **self.review} if declaration is None else declaration
        sig = self.signer.sign(mod.DOMAIN + mod.canonical_declaration(body))
        return {"declaration": copy.deepcopy(body), "key_id": self.key_id,
                "signature_b64": base64.b64encode(sig).decode()}

    def check(self, envelope=None, dossier=None, registry=None, keys=None,
              roots=None, revoked=None, at=None, revision=7):
        out = mod.verify_declaration(
            self.dossier if dossier is None else dossier,
            self.envelope() if envelope is None else envelope,
            self.keys if keys is None else keys,
            set() if revoked is None else revoked,
            self.registry if registry is None else registry,
            self.roots if roots is None else roots,
            self.at if at is None else at, revision
        )
        self.assertEqual(out["release_gate"], "HOLD")
        self.assertFalse(out["authorization_granted"])
        self.assertFalse(out["recovery_approved"])
        self.assertFalse(out["automatic_restore"])
        return out

    def test_eligible_signature_stays_pending_review(self):
        self.assertTrue(self.check()["review_signature_valid"])
        self.assertEqual(self.check()["state"], "pending-review")

    def test_changed_dossier_quarantined(self):
        changed = copy.deepcopy(self.dossier)
        changed["assessment_reason"] = "forged"
        self.assertEqual(self.check(dossier=changed)["reason"], "dossier-binding-failed")

    def test_declared_decision_differs_from_dossier(self):
        body = {"schema_version": "0.1.0", "dossier_sha256": self.digest,
                **{**self.review, "decision": "defer"}}
        self.assertEqual(self.check(envelope=self.envelope(body))["reason"], "review-claim-binding-failed")

    def test_revoked_key_quarantined(self):
        self.assertEqual(self.check(revoked={self.key_id})["reason"], "reviewer-key-revoked")

    def test_revoked_signed_reviewer_quarantined(self):
        self.assertEqual(self.check(registry=self.make_registry(True))["reason"], "reviewer-revoked")

    def test_expired_reviewer_quarantined(self):
        self.assertEqual(self.check(at="2027-01-01T00:00:00Z")["reason"], "reviewer-outside-validity")

    def test_untrusted_issuer_quarantined(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-issuer")

    def test_untrusted_review_key_quarantined(self):
        self.assertEqual(self.check(keys={})["reason"], "untrusted-reviewer-key")

    def test_invalid_signature_quarantined(self):
        e = self.envelope()
        e["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(envelope=e)["reason"], "invalid-review-signature")

    def test_signed_data_mutation_quarantined(self):
        e = self.envelope()
        e["declaration"]["reason"] = "tampered"
        self.assertEqual(self.check(envelope=e)["reason"], "review-claim-binding-failed")

    def test_stale_registry_quarantined(self):
        self.assertEqual(self.check(revision=8)["reason"], "stale-registry-revision")

    def test_approve_decision_disallowed(self):
        body = {"schema_version": "0.1.0", "dossier_sha256": self.digest,
                **{**self.review, "decision": "approve"}}
        with self.assertRaisesRegex(ValueError, "unsupported-review-decision"):
            self.envelope(body)

    def test_unsigned_extra_authority_field_denied(self):
        e = self.envelope()
        e["grant"] = True
        self.assertEqual(self.check(envelope=e)["reason"], "invalid-envelope")

    def test_invalid_revoke_list_denied(self):
        self.assertEqual(self.check(revoked={"not-a-key"})["reason"], "invalid-revocation-list")


if __name__ == "__main__":
    unittest.main()
