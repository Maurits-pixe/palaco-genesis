"""v20 synthetic Ed25519 coordinator receipt regression checks.

Ephemeral keys/test policy callbacks do not establish real signer identity.
"""
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atomic_replay_authority_v19 import AtomicReplayAuthority, AuthorityError
from distributed_replay_v18 import (
    candidate, receipt_statement, inspect_decisions,
)
from offline_stage import _canonical
from signed_authority_receipts_v20 import (
    SignedReceiptError, SignedReceiptIssuer, SignedReceiptVerifier,
)


class SignedReceiptsTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.claim = candidate("sender", "recipient", "message", "a"*64, "device")
        self.statement = receipt_statement(
            self.claim, authority_sequence=1, decision="first-claim")
        self.issuer = SignedReceiptIssuer(
            self.private, key_id="authority-test",
            authorize_sign=lambda *_: True)
        self.verify = self.verifier()

    def verifier(self, **kwargs):
        opts = dict(
            verify_key_policy=lambda *_: True,
            verify_committed=lambda _: True)
        opts.update(kwargs)
        return SignedReceiptVerifier(
            {"authority-test": self.public}, **opts)

    def test_valid_synthetic_receipt(self):
        proof = self.issuer(self.statement)
        self.assertIs(self.verify(self.statement, proof), True)

    def test_wrong_statement(self):
        proof = self.issuer(self.statement)
        other = receipt_statement(self.claim, authority_sequence=2, decision="duplicate")
        self.assertIs(self.verify(other, proof), False)

    def test_tampered_signature(self):
        proof = json.loads(self.issuer(self.statement))
        proof["signature_b64"] = "A" * 88
        self.assertIs(self.verify(self.statement, _canonical(proof).decode()), False)

    def test_wrong_authority_key(self):
        other = Ed25519PrivateKey.generate()
        other_public = other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        verifier = SignedReceiptVerifier(
            {"authority-test": other_public},
            verify_key_policy=lambda *_: True,
            verify_committed=lambda _: True)
        self.assertIs(verifier(self.statement, self.issuer(self.statement)), False)

    def test_revocation_denied(self):
        verifier = self.verifier(verify_key_policy=lambda *_: False)
        self.assertIs(verifier(self.statement, self.issuer(self.statement)), False)

    def test_nonboolean_key_policy_denied(self):
        verifier = self.verifier(verify_key_policy=lambda *_: 1)
        self.assertIs(verifier(self.statement, self.issuer(self.statement)), False)

    def test_uncommitted_decision_denied(self):
        verifier = self.verifier(verify_committed=lambda _: False)
        self.assertIs(verifier(self.statement, self.issuer(self.statement)), False)

    def test_nonboolean_commit_denied(self):
        verifier = self.verifier(verify_committed=lambda _: 1)
        self.assertIs(verifier(self.statement, self.issuer(self.statement)), False)

    def test_commit_provider_exception_denied(self):
        def error(_):
            raise ConnectionError("external checkpoint unavailable")
        verifier = self.verifier(verify_committed=error)
        self.assertIs(verifier(self.statement, self.issuer(self.statement)), False)

    def test_missing_commit_provider_denied(self):
        with self.assertRaisesRegex(SignedReceiptError, "EXTERNAL_TRUST_REQUIRED"):
            self.verifier(verify_committed=None)

    def test_missing_key_policy_denied(self):
        with self.assertRaisesRegex(SignedReceiptError, "EXTERNAL_TRUST_REQUIRED"):
            self.verifier(verify_key_policy=None)

    def test_empty_key_registry_denied(self):
        with self.assertRaisesRegex(SignedReceiptError, "INVALID_TRUST_STORE"):
            SignedReceiptVerifier(
                {}, verify_key_policy=lambda *_: True,
                verify_committed=lambda _: True)

    def test_signing_policy_denied(self):
        issuer = SignedReceiptIssuer(
            self.private, key_id="authority-test",
            authorize_sign=lambda *_: False)
        with self.assertRaisesRegex(SignedReceiptError, "SIGNING_DENIED"):
            issuer(self.statement)

    def test_signing_policy_nonboolean_denied(self):
        issuer = SignedReceiptIssuer(
            self.private, key_id="authority-test",
            authorize_sign=lambda *_: 1)
        with self.assertRaisesRegex(SignedReceiptError, "SIGNING_DENIED"):
            issuer(self.statement)

    def test_signing_policy_exception(self):
        def error(*_):
            raise ConnectionError("key service unavailable")
        issuer = SignedReceiptIssuer(
            self.private, key_id="authority-test",
            authorize_sign=error)
        with self.assertRaisesRegex(SignedReceiptError, "SIGNING_POLICY_UNAVAILABLE"):
            issuer(self.statement)

    def test_non_v18_statement_denied(self):
        with self.assertRaisesRegex(SignedReceiptError, "INVALID_STATEMENT"):
            self.issuer(b"arbitrary-message")
        self.assertIs(self.verify(b"arbitrary-message", "bad"), False)

    def test_noncanonical_proof_denied(self):
        self.assertIs(self.verify(self.statement, self.issuer(self.statement) + " "), False)

    def test_unknown_proof_field_denied(self):
        proof = json.loads(self.issuer(self.statement))
        proof["authorization"] = "ALLOW"
        self.assertIs(self.verify(self.statement, _canonical(proof).decode()), False)

    def test_wrong_key_id_denied(self):
        proof = json.loads(self.issuer(self.statement))
        proof["key_id"] = "untrusted"
        self.assertIs(self.verify(self.statement, _canonical(proof).decode()), False)

    def test_v19_v18_interop_diagnostic(self):
        with tempfile.TemporaryDirectory() as td:
            authority = AtomicReplayAuthority(
                Path(td) / "authority.sqlite",
                authorize_candidate=lambda _: True,
                sign_receipt=self.issuer)
            authority.decide(self.claim)
            claims, receipts = authority.read_decisions()
            report = inspect_decisions(
                claims, receipts, verify_authority=self.verify,
                get_trusted_watermark=lambda: 1)
            self.assertEqual(report["authorization"], "DENY")
            self.assertEqual(report["release"], "HOLD")
            self.assertIs(report["production_release_enabled"], False)

    def test_v19_rejects_signer_denial(self):
        with tempfile.TemporaryDirectory() as td:
            issuer = SignedReceiptIssuer(
                self.private, key_id="authority-test",
                authorize_sign=lambda *_: False)
            authority = AtomicReplayAuthority(
                Path(td) / "authority.sqlite",
                authorize_candidate=lambda _: True, sign_receipt=issuer)
            with self.assertRaisesRegex(AuthorityError, "SIGNING_UNAVAILABLE"):
                authority.decide(self.claim)
            self.assertEqual(authority.read_decisions(), ((), ()))

    def test_receipt_does_not_expose_secret_key(self):
        proof = self.issuer(self.statement)
        self.assertEqual(set(json.loads(proof)), {"key_id", "signature_b64"})
        self.assertNotIn("private", proof)


if __name__ == "__main__":
    unittest.main()
