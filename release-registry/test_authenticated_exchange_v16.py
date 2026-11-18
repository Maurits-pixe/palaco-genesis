"""Synthetic v16 Ed25519 signing / replay-gate regression tests."""
import base64
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from offline_stage import _canonical
from authenticated_exchange_v16 import (
    AuthenticatedExchangeError, sign_exchange, receive_exchange)
from ed25519_trust_v7 import Ed25519TrustAdapter


class AuthenticatedExchangeTests(unittest.TestCase):
    def setUp(self):
        self.signing_key = Ed25519PrivateKey.generate()
        public = self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.verifier = Ed25519TrustAdapter(
            {"sender-01": public}, verify_policy=lambda *_: True)
        self.recipient = X25519PrivateKey.generate()
        self.recipient_public = self.recipient.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.claimed = set()
        self.payload = b"synthetic-v14-bundle-not-authenticated"

    def seal(self, **kwargs):
        opts = dict(bundle=self.payload, sender_id="sender-01",
                    sender_private_key=self.signing_key,
                    recipient_id="recipient-01",
                    recipient_public_key=self.recipient_public,
                    authorize_send=lambda *_: True)
        opts.update(kwargs)
        return sign_exchange(**opts)

    def claim(self, sender, recipient, message, digest):
        identity = (sender, recipient, message)
        if identity in self.claimed:
            return False
        self.claimed.add(identity)
        return True

    def receive(self, package, **kwargs):
        opts = dict(expected_recipient_id="recipient-01",
                    recipient_private_key=self.recipient,
                    verify_sender=self.verifier, claim_replay=self.claim)
        opts.update(kwargs)
        return receive_exchange(package, **opts)

    def test_roundtrip_denies_authority(self):
        body, report = self.receive(self.seal())
        self.assertEqual(body, self.payload)
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_exact_replay_denied(self):
        package = self.seal()
        self.receive(package)
        with self.assertRaisesRegex(AuthenticatedExchangeError, "REPLAY_DENIED"):
            self.receive(package)

    def test_same_message_id_new_ciphertext_denied(self):
        a = self.seal(message_id="same-id")
        b = self.seal(message_id="same-id")
        self.receive(a)
        with self.assertRaisesRegex(AuthenticatedExchangeError, "REPLAY_DENIED"):
            self.receive(b)

    def test_valid_distinct_messages(self):
        self.receive(self.seal(message_id="one"))
        self.receive(self.seal(message_id="two"))
        self.assertEqual(len(self.claimed), 2)

    def test_tampered_message_id(self):
        obj = json.loads(self.seal())
        obj["message_id"] = "changed"
        with self.assertRaisesRegex(AuthenticatedExchangeError, "SENDER_UNVERIFIED"):
            self.receive(_canonical(obj))

    def test_tampered_envelope(self):
        obj = json.loads(self.seal())
        b64 = obj["envelope_b64"]
        obj["envelope_b64"] = ("A" if b64[0] != "A" else "B") + b64[1:]
        with self.assertRaises(AuthenticatedExchangeError):
            self.receive(_canonical(obj))

    def test_forged_sender_id(self):
        obj = json.loads(self.seal())
        obj["sender_id"] = "unknown-sender"
        with self.assertRaisesRegex(AuthenticatedExchangeError, "SENDER_UNVERIFIED"):
            self.receive(_canonical(obj))

    def test_wrong_recipient(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "RECIPIENT_MISMATCH"):
            self.receive(self.seal(), expected_recipient_id="another")

    def test_no_sender_verifier(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "TRUST_SERVICES_REQUIRED"):
            self.receive(self.seal(), verify_sender=None)

    def test_no_replay_provider(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "TRUST_SERVICES_REQUIRED"):
            self.receive(self.seal(), claim_replay=None)

    def test_sender_policy_denial(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "SENDER_UNVERIFIED"):
            self.receive(self.seal(), verify_sender=lambda *_: False)

    def test_sender_truthy_integer_denied(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "SENDER_UNVERIFIED"):
            self.receive(self.seal(), verify_sender=lambda *_: 1)

    def test_replay_provider_exception(self):
        def unavailable(*_):
            raise ConnectionError("storage offline")
        with self.assertRaisesRegex(AuthenticatedExchangeError, "REPLAY_SERVICE_UNAVAILABLE"):
            self.receive(self.seal(), claim_replay=unavailable)

    def test_replay_provider_truthy_integer_denied(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "REPLAY_DENIED"):
            self.receive(self.seal(), claim_replay=lambda *_: 1)

    def test_broken_signature_denied(self):
        obj = json.loads(self.seal())
        obj["signature_b64"] = base64.b64encode(bytes(64)).decode("ascii")
        with self.assertRaisesRegex(AuthenticatedExchangeError, "SENDER_UNVERIFIED"):
            self.receive(_canonical(obj))

    def test_noncanonical_json_denied(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "INVALID_PACKAGE"):
            self.receive(self.seal() + b" ")

    def test_untrusted_send_policy_denied(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "SEAL_DENIED"):
            self.seal(authorize_send=lambda *_: False)

    def test_wrong_recipient_key_denied(self):
        stranger = X25519PrivateKey.generate()
        with self.assertRaises(AuthenticatedExchangeError):
            self.receive(self.seal(), recipient_private_key=stranger)
        self.assertFalse(self.claimed)

    def test_bad_sender_key_denied(self):
        with self.assertRaisesRegex(AuthenticatedExchangeError, "INVALID_SENDER_KEY"):
            self.seal(sender_private_key=bytes(32))

    def test_report_excludes_plaintext(self):
        _, report = self.receive(self.seal())
        self.assertNotIn("synthetic-v14", str(report))


if __name__ == "__main__":
    unittest.main()
