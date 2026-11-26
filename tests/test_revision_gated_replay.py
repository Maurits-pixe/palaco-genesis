"""Regression tests for local revision-floor gating before replay indexing."""
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
spec = importlib.util.spec_from_file_location("revision_gate", ROOT / "tools" / "revision_gated_replay.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RevisionGatedReplayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.revisions = Path(temp.name) / "revisions.sqlite"
        self.replay = Path(temp.name) / "replay.sqlite"
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))
        self.signer_pub = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        issuer_pub = self.issuer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.signer_id = hashlib.sha256(self.signer_pub).hexdigest()
        self.issuer_id = hashlib.sha256(issuer_pub).hexdigest()
        self.signer_keys = {self.signer_id: self.signer_pub}
        self.roots = {self.issuer_id: issuer_pub}
        self.now = "2026-11-22T04:00:00Z"

    def snapshot(self, revision=5, revoked=False):
        body = {"schema_version": "0.1.0", "revision": revision, "reviewers": [{
            "reviewer_id": "reviewer-a", "key_fingerprint": self.signer_id,
            "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
            "revoked": revoked,
        }]}
        sig = self.issuer.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00" + mod.floor._reviewers.canonical(body))
        return {"snapshot": body, "issuer_key_id": self.issuer_id,
                "issuer_signature_b64": base64.b64encode(sig).decode()}

    def item(self, rid):
        payload = {"content": rid}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        metadata = {"schema_version": "0.1.0", "record_id": rid,
                    "lineage_id": "lineage-a", "payload_sha256": digest}
        signature = self.signer.sign(mod.gate.pipeline.signed.canonical_metadata(metadata))
        return {"reviewer_id": "reviewer-a", "candidate": {**metadata, "payload": payload},
                "envelope": {"metadata": metadata, "key_id": self.signer_id,
                             "signature_b64": base64.b64encode(signature).decode()}}

    def evaluate(self, registry=None, items=None, minimum=5, roots=None):
        report = mod.inspect_and_index(
            self.revisions, self.replay, [self.item("rec-a")] if items is None else items,
            self.snapshot() if registry is None else registry,
            self.roots if roots is None else roots, self.signer_keys, self.now, minimum,
        )
        self.assertEqual(report["release_gate"], "HOLD")
        self.assertFalse(report["authorization_granted"])
        self.assertFalse(report["evidence_verified"])
        return report

    def test_first_revision_accepts_for_manual_review(self):
        self.assertEqual(self.evaluate()["decisions"][0]["state"], "pending-review")

    def test_registry_rollback_blocks_new_record(self):
        self.evaluate()
        older = self.snapshot(4)
        result = self.evaluate(older, [self.item("rec-b")], minimum=4)
        self.assertEqual(result["decisions"][0]["reason"], "registry-rollback")

    def test_same_revision_changed_registry_blocks(self):
        self.evaluate()
        changed = self.snapshot(5, revoked=True)
        result = self.evaluate(changed, [self.item("rec-b")])
        self.assertEqual(result["decisions"][0]["reason"], "registry-equivocation")

    def test_newer_revocation_quarantines(self):
        self.evaluate()
        revoked = self.snapshot(6, revoked=True)
        result = self.evaluate(revoked, [self.item("rec-b")])
        self.assertEqual(result["decisions"][0]["reason"], "reviewer-revoked")

    def test_stale_trusted_minimum_is_enforced(self):
        result = self.evaluate(minimum=6)
        self.assertEqual(result["decisions"][0]["reason"], "stale-registry-revision")

    def test_bad_issuer_signature_blocks_before_replay(self):
        bad = self.snapshot()
        bad["issuer_signature_b64"] = base64.b64encode(bytes(64)).decode()
        result = self.evaluate(bad)
        self.assertEqual(result["decisions"][0]["reason"], "invalid-snapshot-signature")
        self.assertFalse(self.replay.exists())

    def test_invalid_signature_never_indexed(self):
        bad = self.item("rec-a")
        bad["envelope"]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.evaluate(items=[bad])
        self.assertFalse(self.replay.exists())
        self.assertEqual(self.evaluate()["decisions"][0]["state"], "pending-review")

    def test_replay_still_quarantined(self):
        self.evaluate()
        self.assertEqual(self.evaluate()["decisions"][0]["reason"], "previously-seen-record-id")

    def test_unknown_issuer_does_not_create_replay(self):
        result = self.evaluate(roots={})
        self.assertEqual(result["decisions"][0]["reason"], "invalid-snapshot-signature")
        self.assertFalse(self.replay.exists())

    def test_same_db_path_rejected(self):
        with self.assertRaises(ValueError):
            mod.inspect_and_index(self.revisions, self.revisions, [], self.snapshot(),
                                  self.roots, self.signer_keys, self.now, 5)


if __name__ == "__main__":
    unittest.main()
