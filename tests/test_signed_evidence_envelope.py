"""Ed25519 signature checks are not identity or authorization decisions."""
import base64
import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("signed_envelope", ROOT / "tools" / "signed_evidence_envelope.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedEnvelopeTests(unittest.TestCase):
    def setUp(self):
        # Fixed private key is a TEST VECTOR only; never use for trusted issuance.
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.key_id = hashlib.sha256(self.public).hexdigest()
        self.trust = {self.key_id: self.public}
        payload = {"content": "example only"}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.meta = {"schema_version": "0.1.0", "record_id": "record-1",
                     "lineage_id": "lineage-1", "payload_sha256": digest}
        self.candidate = {**self.meta, "payload": payload}
        sig = self.private.sign(mod.canonical_metadata(self.meta))
        self.envelope = {"metadata": copy.deepcopy(self.meta), "key_id": self.key_id,
                         "signature_b64": base64.b64encode(sig).decode("ascii")}

    def verdict(self, envelope=None, keys=None):
        result = mod.verify(self.envelope if envelope is None else envelope,
                            self.trust if keys is None else keys)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertIs(result["authorization_granted"], False)
        return result

    def test_valid_signature_never_grants_authority(self):
        result = self.verdict()
        self.assertTrue(result["signature_valid"])
        self.assertEqual(result["state"], "pending-review")

    def test_unknown_key_quarantined(self):
        self.assertEqual(self.verdict(keys={})["reason"], "untrusted-key")

    def test_modified_metadata_rejected(self):
        item = copy.deepcopy(self.envelope)
        item["metadata"]["record_id"] = "record-2"
        self.assertEqual(self.verdict(item)["reason"], "invalid-signature")

    def test_signature_tampering_rejected(self):
        item = copy.deepcopy(self.envelope)
        item["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.verdict(item)["reason"], "invalid-signature")

    def test_key_fingerprint_mismatch_rejected(self):
        self.assertEqual(self.verdict(keys={self.key_id: bytes(32)})["reason"],
                         "key-fingerprint-mismatch")

    def test_unsigned_fields_rejected(self):
        item = copy.deepcopy(self.envelope)
        item["authority"] = "OWNER"
        self.assertEqual(self.verdict(item)["reason"], "invalid-envelope")

    def test_bad_base64_rejected(self):
        item = copy.deepcopy(self.envelope)
        item["signature_b64"] = "!"
        self.assertEqual(self.verdict(item)["reason"], "invalid-signature-format")

    def test_malformed_metadata_rejected(self):
        item = copy.deepcopy(self.envelope)
        item["metadata"]["payload_sha256"] = []
        self.assertEqual(self.verdict(item)["reason"], "invalid-payload-digest")

    def test_missing_trust_map_rejected(self):
        self.assertEqual(self.verdict(keys=None if False else [])["reason"], "missing-trust-map")

    def test_candidate_payload_binding(self):
        result = mod.verify_candidate(self.envelope, self.candidate, self.trust)
        self.assertTrue(result["signature_valid"])
        self.assertEqual(result["state"], "pending-review")

    def test_modified_candidate_rejected(self):
        item = copy.deepcopy(self.candidate)
        item["payload"]["content"] = "tampered"
        result = mod.verify_candidate(self.envelope, item, self.trust)
        self.assertEqual(result["reason"], "candidate-binding-failed")

    def test_other_candidate_id_rejected(self):
        item = copy.deepcopy(self.candidate)
        item["record_id"] = "record-else"
        result = mod.verify_candidate(self.envelope, item, self.trust)
        self.assertEqual(result["reason"], "candidate-binding-failed")


if __name__ == "__main__":
    unittest.main()
