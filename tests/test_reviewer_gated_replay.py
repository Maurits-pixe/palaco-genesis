"""Reviewer-gated signature/replay pipeline regression tests."""
import base64
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reviewer_gate", ROOT / "tools" / "reviewer_gated_replay.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReviewerGatedReplayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "local-index.sqlite"
        self.reviewer_private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.issuer_private = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))
        self.reviewer_public = self.reviewer_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        issuer_public = self.issuer_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.reviewer_fingerprint = hashlib.sha256(self.reviewer_public).hexdigest()
        self.issuer_fingerprint = hashlib.sha256(issuer_public).hexdigest()
        self.evidence_keys = {self.reviewer_fingerprint: self.reviewer_public}
        self.issuer_roots = {self.issuer_fingerprint: issuer_public}
        self.at = "2026-11-22T04:00:00Z"
        self.snapshot = {
            "schema_version": "0.1.0", "revision": 5,
            "reviewers": [{
                "reviewer_id": "reviewer-a",
                "key_fingerprint": self.reviewer_fingerprint,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "revoked": False,
            }],
        }

    def registry(self, snapshot=None):
        snap = copy.deepcopy(self.snapshot if snapshot is None else snapshot)
        payload = gate.reviewers.canonical(snap)
        signature = self.issuer_private.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00" + payload)
        return {
            "snapshot": snap, "issuer_key_id": self.issuer_fingerprint,
            "issuer_signature_b64": base64.b64encode(signature).decode(),
        }

    def item(self, rid="record-a"):
        payload = {"content": "untrusted"}
        digest = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        metadata = {
            "schema_version": "0.1.0", "record_id": rid,
            "lineage_id": "lineage-a", "payload_sha256": digest,
        }
        signature = self.reviewer_private.sign(gate.pipeline.signed.canonical_metadata(metadata))
        return {
            "reviewer_id": "reviewer-a", "candidate": {**metadata, "payload": payload},
            "envelope": {
                "metadata": metadata,
                "key_id": self.reviewer_fingerprint,
                "signature_b64": base64.b64encode(signature).decode(),
            },
        }

    def check(self, items, registry=None, roots=None, keys=None, at=None, revision=5):
        result = gate.inspect_and_index(
            self.db, items, self.registry() if registry is None else registry,
            self.issuer_roots if roots is None else roots,
            self.evidence_keys if keys is None else keys,
            self.at if at is None else at, revision,
        )
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertIs(result["authorization_granted"], False)
        self.assertIs(result["evidence_verified"], False)
        self.assertIs(result["signer_authority_verified"], False)
        return result["decisions"]

    def test_eligible_signed_candidate_pending_review(self):
        self.assertEqual(self.check([self.item()])[0]["state"], "pending-review")

    def test_revoked_reviewer_not_indexed(self):
        snap = copy.deepcopy(self.snapshot)
        snap["reviewers"][0]["revoked"] = True
        self.assertEqual(self.check([self.item()], registry=self.registry(snap))[0]["reason"],
                         "reviewer-revoked")
        self.assertFalse(self.db.exists())

    def test_expired_reviewer_not_indexed(self):
        self.assertEqual(self.check([self.item()], at="2027-01-01T00:00:00Z")[0]["reason"],
                         "reviewer-outside-validity")
        self.assertFalse(self.db.exists())

    def test_stale_revision_not_indexed(self):
        self.assertEqual(self.check([self.item()], revision=6)[0]["reason"],
                         "stale-registry-revision")
        self.assertFalse(self.db.exists())

    def test_unknown_registry_issuer_not_indexed(self):
        self.assertEqual(self.check([self.item()], roots={})[0]["reason"], "untrusted-issuer")
        self.assertFalse(self.db.exists())

    def test_reviewer_fingerprint_mismatch_not_indexed(self):
        item = self.item()
        item["envelope"]["key_id"] = "0" * 64
        self.assertEqual(self.check([item])[0]["reason"], "reviewer-key-mismatch")
        self.assertFalse(self.db.exists())

    def test_invalid_evidence_signature_not_indexed(self):
        item = self.item()
        item["envelope"]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check([item])[0]["reason"], "invalid-signature")
        self.assertFalse(self.db.exists())

    def test_duplicate_record_quarantined(self):
        self.check([self.item()])
        self.assertEqual(self.check([self.item()])[0]["reason"], "previously-seen-record-id")

    def test_mixed_batch_preserves_indices(self):
        bad = self.item("bad")
        bad["envelope"]["key_id"] = "0" * 64
        report = self.check([bad, self.item("good")])
        self.assertEqual([d["index"] for d in report], [0, 1])
        self.assertEqual([d["state"] for d in report], ["quarantined", "pending-review"])

    def test_invalid_item_rejected(self):
        self.assertEqual(self.check([None])[0]["reason"], "invalid-item")

    def test_malformed_registry_treated_as_quarantine(self):
        self.assertEqual(self.check([self.item()], registry={})[0]["reason"], "invalid-envelope")
        self.assertFalse(self.db.exists())

    def test_no_mutation(self):
        entries = [self.item()]
        original = copy.deepcopy(entries)
        self.check(entries)
        self.assertEqual(entries, original)


if __name__ == "__main__":
    unittest.main()
