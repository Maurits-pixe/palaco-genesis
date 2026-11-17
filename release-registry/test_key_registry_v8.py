"""Synthetic key-registry tests. These do not establish external trust."""
import base64
import copy
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from key_registry_v8 import AnchoredRegistry, RegistryError, SCHEMA, snapshot_digest


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.document = {
            "schema": SCHEMA,
            "version": 3,
            "keys": [{
                "key_id": "test-key",
                "public_key_b64": base64.b64encode(self.public).decode("ascii"),
                "status": "active",
                "scopes": ["candidate-a"],
            }],
        }
        self.statement = b"PALACO-TRUSTED-EVIDENCE-v6:ATTESTATION\x00fixture"
        self.signature = base64.b64encode(self.private.sign(self.statement)).decode()

    def adapter(self, document=None, *, anchor=None, current=None):
        doc = self.document if document is None else document
        digest = snapshot_digest(doc)
        return AnchoredRegistry(
            doc, scope="candidate-a",
            get_anchor=(lambda: (doc["version"], digest)) if anchor is None else anchor,
            check_current=(lambda *_: True) if current is None else current)

    def test_synthetic_positive(self):
        self.assertIs(self.adapter()(self.statement, self.signature, "test-key"), True)

    def test_revoked_fails(self):
        doc = copy.deepcopy(self.document)
        doc["keys"][0]["status"] = "revoked"
        self.assertIs(self.adapter(doc)(self.statement, self.signature, "test-key"), False)

    def test_missing_scope_fails(self):
        doc = copy.deepcopy(self.document)
        doc["keys"][0]["scopes"] = ["another-scope"]
        self.assertIs(self.adapter(doc)(self.statement, self.signature, "test-key"), False)

    def test_old_version_fails(self):
        self.assertIs(self.adapter(anchor=lambda: (4, "0"*64))(
            self.statement, self.signature, "test-key"), False)

    def test_modified_registry_fails(self):
        self.assertIs(self.adapter(anchor=lambda: (3, "0"*64))(
            self.statement, self.signature, "test-key"), False)

    def test_offline_policy_denied(self):
        self.assertIs(self.adapter(current=lambda *_: False)(
            self.statement, self.signature, "test-key"), False)

    def test_truthy_policy_denied(self):
        self.assertIs(self.adapter(current=lambda *_: 1)(
            self.statement, self.signature, "test-key"), False)

    def test_anchor_unavailable_denied(self):
        def fail():
            raise ConnectionError("offline")
        self.assertIs(self.adapter(anchor=fail)(
            self.statement, self.signature, "test-key"), False)

    def test_current_policy_exception_denied(self):
        def fail(*_):
            raise ConnectionError("revocation unknown")
        self.assertIs(self.adapter(current=fail)(
            self.statement, self.signature, "test-key"), False)

    def test_unknown_key_denied(self):
        self.assertIs(self.adapter()(
            self.statement, self.signature, "unknown"), False)

    def test_modified_signature_denied(self):
        self.assertIs(self.adapter()(
            self.statement + b"!", self.signature, "test-key"), False)

    def test_duplicate_key_rejected(self):
        doc = copy.deepcopy(self.document)
        doc["keys"].append(copy.deepcopy(doc["keys"][0]))
        with self.assertRaises(RegistryError):
            snapshot_digest(doc)

    def test_unknown_field_rejected(self):
        doc = copy.deepcopy(self.document)
        doc["authorized"] = True
        with self.assertRaises(RegistryError):
            snapshot_digest(doc)

    def test_duplicate_scope_rejected(self):
        doc = copy.deepcopy(self.document)
        doc["keys"][0]["scopes"] = ["candidate-a", "candidate-a"]
        with self.assertRaises(RegistryError):
            snapshot_digest(doc)

    def test_noncanonical_key_encoding_rejected(self):
        doc = copy.deepcopy(self.document)
        doc["keys"][0]["public_key_b64"] = doc["keys"][0]["public_key_b64"].rstrip("=")
        with self.assertRaises(RegistryError):
            snapshot_digest(doc)

    def test_boolean_version_rejected(self):
        doc = copy.deepcopy(self.document)
        doc["version"] = True
        with self.assertRaises(RegistryError):
            snapshot_digest(doc)

    def test_missing_trust_sources_rejected(self):
        with self.assertRaises(RegistryError):
            AnchoredRegistry(self.document, scope="candidate-a",
                             get_anchor=None, check_current=None)

    def test_fingerprint_stable(self):
        self.assertEqual(self.adapter().fingerprint, snapshot_digest(self.document))

    def test_malformed_anchor_denied(self):
        self.assertIs(self.adapter(anchor=lambda: [3, snapshot_digest(self.document)])(
            self.statement, self.signature, "test-key"), False)


if __name__ == "__main__":
    unittest.main()
