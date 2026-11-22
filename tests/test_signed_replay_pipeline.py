"""Positive and negative checks for signature-first replay intake."""
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
spec = importlib.util.spec_from_file_location("signed_replay", ROOT / "tools" / "signed_replay_pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class SignedReplayPipelineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "local.sqlite"
        private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))  # TEST KEY ONLY
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.private = private
        self.key_id = hashlib.sha256(public).hexdigest()
        self.keys = {self.key_id: public}

    def item(self, record_id="record-a", content="alpha"):
        payload = {"data": content}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        metadata = {
            "schema_version": "0.1.0", "record_id": record_id,
            "lineage_id": "lineage-a", "payload_sha256": digest,
        }
        signature = self.private.sign(pipeline.signed.canonical_metadata(metadata))
        return {
            "candidate": {**metadata, "payload": payload},
            "envelope": {
                "metadata": metadata, "key_id": self.key_id,
                "signature_b64": base64.b64encode(signature).decode(),
            },
        }

    def check(self, items, keys=None):
        result = pipeline.inspect_and_index(self.db, items, self.keys if keys is None else keys)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["evidence_verified"])
        self.assertFalse(result["signer_authority_verified"])
        return result["decisions"]

    def test_signed_candidate_still_pending_review(self):
        self.assertEqual(self.check([self.item()])[0]["state"], "pending-review")

    def test_replayed_signature_quarantined(self):
        self.check([self.item()])
        self.assertEqual(self.check([self.item()])[0]["reason"], "previously-seen-record-id")

    def test_invalid_signature_does_not_poison_index(self):
        tampered = self.item()
        tampered["envelope"]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check([tampered])[0]["reason"], "invalid-signature")
        self.assertFalse(self.db.exists())
        self.assertEqual(self.check([self.item()])[0]["state"], "pending-review")

    def test_tampered_payload_does_not_poison_index(self):
        tampered = self.item()
        tampered["candidate"]["payload"]["data"] = "corrupted"
        self.assertEqual(self.check([tampered])[0]["reason"], "candidate-binding-failed")
        self.assertEqual(self.check([self.item()])[0]["state"], "pending-review")

    def test_unknown_key_quarantined(self):
        self.assertEqual(self.check([self.item()], keys={})[0]["reason"], "untrusted-key")

    def test_duplicate_signed_batch_quarantined(self):
        item = self.item()
        decisions = self.check([item, copy.deepcopy(item)])
        self.assertEqual([x["state"] for x in decisions], ["quarantined", "quarantined"])
        self.assertEqual(self.check([self.item()])[0]["state"], "pending-review")

    def test_mixed_batch_preserves_original_positions(self):
        bad = self.item("bad")
        bad["candidate"]["payload"]["data"] = "wrong"
        decisions = self.check([bad, self.item("good")])
        self.assertEqual([x["index"] for x in decisions], [0, 1])
        self.assertEqual([x["state"] for x in decisions], ["quarantined", "pending-review"])

    def test_invalid_item_rejected(self):
        self.assertEqual(self.check([None])[0]["reason"], "invalid-item")

    def test_overlimit_rejected(self):
        with self.assertRaises(ValueError):
            self.check([None] * (pipeline.MAX_BATCH + 1))

    def test_invalid_keys_rejected_without_writes(self):
        with self.assertRaises(ValueError):
            self.check([self.item()], keys=[])
        self.assertFalse(self.db.exists())

    def test_input_not_modified(self):
        items = [self.item()]
        previous = copy.deepcopy(items)
        self.check(items)
        self.assertEqual(items, previous)


if __name__ == "__main__":
    unittest.main()
