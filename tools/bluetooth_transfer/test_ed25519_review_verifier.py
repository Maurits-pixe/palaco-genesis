"""Real Ed25519 verification regressions; test private keys never committed."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ed25519_review_verifier import (
    Ed25519ReviewVerifier, ReviewerPublicKey, REVIEW_ROLE,
)
from protocol import TransferError
from recovery_evidence import build_evidence
from recovery_inspection import RecoveryReport, RecoveryStatus
from signed_review_gate import (
    SignedReviewSubmission, ReviewDisposition, signing_message,
    assess_review_submission,
)


class Ed25519ReviewTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.entry = ReviewerPublicKey(raw, REVIEW_ROLE, False, 100, 200)
        self.clock_value = 150
        self.keys = {"reviewer-01": self.entry}
        self.verifier = Ed25519ReviewVerifier(
            self.keys, lambda: self.clock_value,
        )
        self.evidence = build_evidence(
            RecoveryReport(RecoveryStatus.UNAVAILABLE, None, None, None, None),
        )
        self.challenge = b"fresh-challenge-for-review-001"
        self.message = signing_message(self.evidence, self.challenge)
        self.submission = SignedReviewSubmission(
            self.evidence, "reviewer-01",
            self.challenge, self.private.sign(self.message),
        )

    def test_actual_signature_is_valid(self):
        self.assertTrue(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_signed_submission_only_hold_reviewable(self):
        self.assertIs(
            assess_review_submission(self.submission, self.verifier),
            ReviewDisposition.HOLD_REVIEWABLE,
        )

    def test_wrong_signing_key(self):
        self.assertFalse(self.verifier.verify(
            "reviewer-01", self.message, self.other.sign(self.message),
        ))

    def test_changed_message(self):
        self.assertFalse(self.verifier.verify(
            "reviewer-01", self.message + b"x", self.submission.signature,
        ))

    def test_changed_challenge_binding(self):
        altered = signing_message(self.evidence, b"another-challenge-review-002")
        self.assertFalse(self.verifier.verify(
            "reviewer-01", altered, self.submission.signature,
        ))

    def test_short_signature(self):
        self.assertFalse(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature[:32],
        ))

    def test_unknown_key(self):
        self.assertFalse(self.verifier.verify(
            "missing", self.message, self.submission.signature,
        ))

    def test_revoked_key(self):
        verifier = Ed25519ReviewVerifier(
            {"reviewer-01": replace(self.entry, revoked=True)},
            lambda: 150,
        )
        self.assertFalse(verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_wrong_role(self):
        verifier = Ed25519ReviewVerifier(
            {"reviewer-01": replace(self.entry, role="owner")},
            lambda: 150,
        )
        self.assertFalse(verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_before_validity(self):
        self.clock_value = 99
        self.assertFalse(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_end_validity_exclusive(self):
        self.clock_value = 200
        self.assertFalse(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_at_validity_start(self):
        self.clock_value = 100
        self.assertTrue(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_invalid_time_type(self):
        self.clock_value = True
        self.assertFalse(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_clock_exception_fails_closed(self):
        verifier = Ed25519ReviewVerifier(self.keys, lambda: 1 / 0)
        self.assertFalse(verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_input_registry_copied(self):
        self.keys.clear()
        self.assertTrue(self.verifier.verify(
            "reviewer-01", self.message, self.submission.signature,
        ))

    def test_invalid_raw_key_length(self):
        with self.assertRaises(TransferError):
            ReviewerPublicKey(b"short", REVIEW_ROLE, False, 100, 200)

    def test_invalid_role_entry(self):
        with self.assertRaises(TransferError):
            ReviewerPublicKey(self.entry.public_key_raw, 1, False, 100, 200)

    def test_boolean_revocation_required(self):
        with self.assertRaises(TransferError):
            ReviewerPublicKey(self.entry.public_key_raw, REVIEW_ROLE, 0, 100, 200)

    def test_invalid_window(self):
        with self.assertRaises(TransferError):
            ReviewerPublicKey(self.entry.public_key_raw, REVIEW_ROLE, False, 200, 100)

    def test_invalid_key_id(self):
        with self.assertRaises(TransferError):
            Ed25519ReviewVerifier({"../bad": self.entry}, lambda: 150)

    def test_empty_registry(self):
        with self.assertRaises(TransferError):
            Ed25519ReviewVerifier({}, lambda: 150)

    def test_no_clock(self):
        with self.assertRaises(TransferError):
            Ed25519ReviewVerifier({"reviewer-01": self.entry}, None)

    def test_signature_rejects_boolean_message(self):
        self.assertFalse(self.verifier.verify(
            "reviewer-01", True, self.submission.signature,
        ))

    def test_no_private_key_export_in_registry(self):
        self.assertEqual(len(self.entry.public_key_raw), 32)
        self.assertNotIn("PRIVATE", repr(self.entry))


if __name__ == "__main__":
    unittest.main()
