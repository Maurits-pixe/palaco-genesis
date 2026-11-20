"""PALACO v15 encrypted exchange tests, using ephemeral synthetic keys."""
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from offline_stage import _canonical
from secure_evidence_exchange_v15 import (
    ExchangeError, seal_bundle, open_bundle, SCHEMA,
)


class SecureExchangeTests(unittest.TestCase):
    def setUp(self):
        self.recipient = X25519PrivateKey.generate()
        self.other = X25519PrivateKey.generate()
        self.public = self.recipient.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.plaintext = b'{"schema":"palaco-governance-proof-bundle/v14","test":"synthetic"}'

    def seal(self, **kwargs):
        params = {"recipient_id": "reviewer-001",
                  "recipient_public_key": self.public,
                  "authorize_send": lambda *_: True}
        params.update(kwargs)
        return seal_bundle(self.plaintext, **params)

    def open(self, encrypted, **kwargs):
        params = {"expected_recipient_id": "reviewer-001",
                  "recipient_private_key": self.recipient}
        params.update(kwargs)
        return open_bundle(encrypted, **params)

    def test_roundtrip(self):
        self.assertEqual(self.open(self.seal()), self.plaintext)

    def test_probabilistic_sealing(self):
        self.assertNotEqual(self.seal(), self.seal())

    def test_no_policy_denied(self):
        with self.assertRaisesRegex(ExchangeError, "SEND_POLICY_REQUIRED"):
            self.seal(authorize_send=None)

    def test_false_policy_denied(self):
        with self.assertRaisesRegex(ExchangeError, "SEND_DENIED"):
            self.seal(authorize_send=lambda *_: False)

    def test_truthy_nonboolean_policy_denied(self):
        with self.assertRaisesRegex(ExchangeError, "SEND_DENIED"):
            self.seal(authorize_send=lambda *_: 1)

    def test_policy_exception_denied(self):
        def unreachable(*_):
            raise ConnectionError("no independent recipient lookup")
        with self.assertRaisesRegex(ExchangeError, "ENCRYPTION_UNAVAILABLE"):
            self.seal(authorize_send=unreachable)

    def test_wrong_private_key_denied(self):
        with self.assertRaisesRegex(ExchangeError, "DECRYPTION_DENIED"):
            self.open(self.seal(), recipient_private_key=self.other)

    def test_wrong_recipient_id_denied(self):
        with self.assertRaisesRegex(ExchangeError, "RECIPIENT_MISMATCH"):
            self.open(self.seal(), expected_recipient_id="another")

    def test_modified_ciphertext_denied(self):
        data = json.loads(self.seal())
        ct = data["ciphertext_b64"]
        data["ciphertext_b64"] = ("A" if ct[0] != "A" else "B") + ct[1:]
        with self.assertRaises(ExchangeError):
            self.open(_canonical(data))

    def test_modified_nonce_denied(self):
        data = json.loads(self.seal())
        nonce = data["nonce_b64"]
        data["nonce_b64"] = ("A" if nonce[0] != "A" else "B") + nonce[1:]
        with self.assertRaises(ExchangeError):
            self.open(_canonical(data))

    def test_modified_ephemeral_pub_denied(self):
        data = json.loads(self.seal())
        p = data["ephemeral_public_key_b64"]
        data["ephemeral_public_key_b64"] = ("A" if p[0] != "A" else "B") + p[1:]
        with self.assertRaises(ExchangeError):
            self.open(_canonical(data))

    def test_unknown_field_denied(self):
        data = json.loads(self.seal())
        data["authorized"] = True
        with self.assertRaisesRegex(ExchangeError, "INVALID_ENVELOPE_SCHEMA"):
            self.open(_canonical(data))

    def test_noncanonical_json_denied(self):
        with self.assertRaisesRegex(ExchangeError, "INVALID_ENVELOPE_SCHEMA"):
            self.open(self.seal() + b" ")

    def test_invalid_recipient_name_denied(self):
        with self.assertRaisesRegex(ExchangeError, "INVALID_RECIPIENT"):
            self.seal(recipient_id="../../escape")

    def test_invalid_recipient_key_denied(self):
        with self.assertRaisesRegex(ExchangeError, "INVALID_RECIPIENT_KEY"):
            self.seal(recipient_public_key=b"bad")

    def test_zero_length_plaintext_denied(self):
        with self.assertRaisesRegex(ExchangeError, "INVALID_BUNDLE"):
            seal_bundle(b"", recipient_id="reviewer-001",
                        recipient_public_key=self.public,
                        authorize_send=lambda *_: True)

    def test_wrong_private_key_type_denied(self):
        with self.assertRaisesRegex(ExchangeError, "INVALID_PRIVATE_KEY"):
            self.open(self.seal(), recipient_private_key=b"not-a-key")

    def test_report_not_issued_by_decryption(self):
        self.assertEqual(self.open(self.seal()), self.plaintext)
        self.assertNotIn(b'authorization', self.plaintext)
        self.assertNotIn(b'production_release_enabled', self.plaintext)

    def test_envelope_exposes_no_receipts_or_plaintext(self):
        sealed = self.seal()
        self.assertNotIn(self.plaintext, sealed)
        self.assertNotIn(b"synthetic", sealed)
        self.assertEqual(json.loads(sealed)["schema"], SCHEMA)

    def test_too_large_input_denied(self):
        with self.assertRaisesRegex(ExchangeError, "INVALID_BUNDLE"):
            seal_bundle(b"x" * (2_097_153), recipient_id="reviewer-001",
                        recipient_public_key=self.public,
                        authorize_send=lambda *_: True)


if __name__ == "__main__":
    unittest.main()
