"""Ephemeral keys only. No production keys or external trust claims."""
import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ed25519_trust_v7 import Ed25519TrustAdapter, TrustAdapterError


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.statement = b"PALACO-TRUSTED-EVIDENCE-v6:ATTESTATION\x00synthetic"
        self.signature = base64.b64encode(self.private.sign(self.statement)).decode("ascii")
        self.allow = lambda *_: True  # Synthetic isolated test fixture ONLY.

    def adapter(self, *, policy=None):
        return Ed25519TrustAdapter({"fixture-1": self.public},
                                   verify_policy=self.allow if policy is None else policy)

    def test_valid_signature(self):
        self.assertIs(self.adapter()(self.statement, self.signature, "fixture-1"), True)

    def test_tampered_message(self):
        self.assertIs(self.adapter()(self.statement + b"x", self.signature, "fixture-1"), False)

    def test_tampered_signature(self):
        corrupted = bytearray(base64.b64decode(self.signature))
        corrupted[0] ^= 1
        sig = base64.b64encode(corrupted).decode()
        self.assertIs(self.adapter()(self.statement, sig, "fixture-1"), False)

    def test_unknown_key(self):
        self.assertIs(self.adapter()(self.statement, self.signature, "unregistered"), False)

    def test_revoked(self):
        self.assertIs(self.adapter(policy=lambda *_: False)(
            self.statement, self.signature, "fixture-1"), False)

    def test_policy_exception(self):
        def unavailable(*_):
            raise ConnectionError("revocation unavailable")
        self.assertIs(self.adapter(policy=unavailable)(
            self.statement, self.signature, "fixture-1"), False)

    def test_truthy_policy_denied(self):
        self.assertIs(self.adapter(policy=lambda *_: 1)(
            self.statement, self.signature, "fixture-1"), False)

    def test_noncanonical_base64(self):
        self.assertIs(self.adapter()(
            self.statement, self.signature.rstrip("="), "fixture-1"), False)

    def test_bad_signature_length(self):
        self.assertIs(self.adapter()(
            self.statement, base64.b64encode(b"a").decode(), "fixture-1"), False)

    def test_no_policy(self):
        with self.assertRaises(TrustAdapterError):
            Ed25519TrustAdapter({"fixture-1": self.public}, verify_policy=None)

    def test_bad_public_key(self):
        with self.assertRaises(TrustAdapterError):
            Ed25519TrustAdapter({"fixture-1": b"bad"}, verify_policy=self.allow)

    def test_empty_trust_store(self):
        with self.assertRaises(TrustAdapterError):
            Ed25519TrustAdapter({}, verify_policy=self.allow)

    def test_no_key_in_evidence_used(self):
        other = Ed25519PrivateKey.generate()
        other_sig = base64.b64encode(other.sign(self.statement)).decode()
        self.assertIs(self.adapter()(self.statement, other_sig, "fixture-1"), False)

    def test_wrong_key_id(self):
        self.assertIs(self.adapter()(self.statement, self.signature, "fixture-2"), False)

    def test_statement_type(self):
        self.assertIs(self.adapter()("text", self.signature, "fixture-1"), False)


if __name__ == "__main__":
    unittest.main()
