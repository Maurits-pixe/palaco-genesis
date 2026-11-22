"""Negative and positive reviewer registry contract tests."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reviewer_registry", ROOT / "tools" / "signed_reviewer_registry.py")
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)


class ReviewerRegistryTests(unittest.TestCase):
    def setUp(self):
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))  # TEST ONLY
        public = self.issuer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = hashlib.sha256(public).hexdigest()
        self.roots = {self.key_id: public}
        self.reviewer_key = hashlib.sha256(bytes(range(1, 33))).hexdigest()
        self.snapshot = {"schema_version": "0.1.0", "revision": 2, "reviewers": [{
            "reviewer_id": "reviewer-a", "key_fingerprint": self.reviewer_key,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z", "revoked": False
        }]}
        self.at = "2026-11-22T04:00:00Z"

    def envelope(self, snapshot=None):
        snap = copy.deepcopy(self.snapshot if snapshot is None else snapshot)
        signature = self.issuer.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00" + registry.canonical(snap))
        return {"snapshot": snap, "issuer_key_id": self.key_id,
                "issuer_signature_b64": base64.b64encode(signature).decode()}

    def evaluate(self, envelope=None, roots=None, reviewer_key=None, at=None, revision=1):
        result = registry.evaluate(
            self.envelope() if envelope is None else envelope,
            self.roots if roots is None else roots,
            "reviewer-a", self.reviewer_key if reviewer_key is None else reviewer_key,
            self.at if at is None else at, revision
        )
        self.assertFalse(result["authorization_granted"])
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_signed_active_reviewer_still_pending(self):
        result = self.evaluate()
        self.assertTrue(result["reviewer_eligible_for_manual_review"])
        self.assertEqual(result["state"], "pending-review")

    def test_revoked_reviewer_denied(self):
        snap = copy.deepcopy(self.snapshot)
        snap["reviewers"][0]["revoked"] = True
        self.assertEqual(self.evaluate(self.envelope(snap))["reason"], "reviewer-revoked")

    def test_expired_reviewer_denied(self):
        self.assertEqual(self.evaluate(at="2027-01-01T00:00:00Z")["reason"], "reviewer-outside-validity")

    def test_not_yet_valid_denied(self):
        self.assertEqual(self.evaluate(at="2025-12-31T23:59:59Z")["reason"], "reviewer-outside-validity")

    def test_wrong_reviewer_key_denied(self):
        self.assertEqual(self.evaluate(reviewer_key="0" * 64)["reason"], "reviewer-key-mismatch")

    def test_untrusted_issuer_denied(self):
        self.assertEqual(self.evaluate(roots={})["reason"], "untrusted-issuer")

    def test_issuer_signature_tampering_denied(self):
        env = self.envelope()
        env["issuer_signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.evaluate(env)["reason"], "invalid-issuer-signature")

    def test_snapshot_tampering_denied(self):
        env = self.envelope()
        env["snapshot"]["reviewers"][0]["revoked"] = True
        self.assertEqual(self.evaluate(env)["reason"], "invalid-issuer-signature")

    def test_stale_revision_denied(self):
        self.assertEqual(self.evaluate(revision=3)["reason"], "stale-registry-revision")

    def test_duplicate_key_denied(self):
        snap = copy.deepcopy(self.snapshot)
        snap["reviewers"].append({**snap["reviewers"][0], "reviewer_id": "reviewer-b"})
        with self.assertRaisesRegex(ValueError, "duplicate-reviewer-or-key"):
            registry.canonical(snap)

    def test_non_utc_time_denied(self):
        self.assertEqual(self.evaluate(at="2026-11-22T04:00:00+01:00")["reason"], "timestamp-must-be-utc")

    def test_unbounded_elevation_field_denied(self):
        env = self.envelope()
        env["authorization"] = True
        self.assertEqual(self.evaluate(env)["reason"], "invalid-envelope")

    def test_invalid_revocation_type_denied(self):
        snap = copy.deepcopy(self.snapshot)
        snap["reviewers"][0]["revoked"] = "false"
        with self.assertRaisesRegex(ValueError, "invalid-revocation-status"):
            registry.canonical(snap)


if __name__ == "__main__":
    unittest.main()
