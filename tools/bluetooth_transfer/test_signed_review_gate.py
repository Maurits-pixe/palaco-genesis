"""Synthetic signed-review admission tests. Verifier is a fake, not crypto."""
from dataclasses import replace
import hashlib
import unittest

from protocol import TransferError
from recovery_evidence import RecoveryEvidence, build_evidence
from recovery_inspection import RecoveryReport, RecoveryStatus
from signed_review_gate import (
    DOMAIN, ReviewDisposition, SignedReviewSubmission,
    assess_review_submission, signing_message,
)


class FakeVerifier:
    """Test-only deterministic stand-in, NOT a production signature verifier."""

    def __init__(self):
        self.allowed = True
        self.calls = []
        self.fail = False

    def verify(self, key_id, message, signature):
        self.calls.append((key_id, message, signature))
        if self.fail:
            raise OSError("verifier offline")
        return self.allowed and signature == hashlib.sha256(message).digest()


class SignedReviewGateTests(unittest.TestCase):
    def setUp(self):
        report = RecoveryReport(RecoveryStatus.UNAVAILABLE, None, None, None, None)
        self.evidence = build_evidence(report)
        self.challenge = b"unique-test-challenge-001"
        self.verifier = FakeVerifier()
        self.signature = hashlib.sha256(
            signing_message(self.evidence, self.challenge)
        ).digest()
        self.submission = SignedReviewSubmission(
            self.evidence, "reviewer-key-001", self.challenge, self.signature,
        )

    def test_reviewable_is_always_hold(self):
        self.assertEqual(
            assess_review_submission(self.submission, self.verifier),
            ReviewDisposition.HOLD_REVIEWABLE,
        )

    def test_verifier_receives_exact_bound_message(self):
        assess_review_submission(self.submission, self.verifier)
        key_id, message, signature = self.verifier.calls[0]
        self.assertEqual(key_id, "reviewer-key-001")
        self.assertEqual(message, signing_message(self.evidence, self.challenge))
        self.assertEqual(signature, self.signature)
        self.assertTrue(message.startswith(DOMAIN))

    def test_missing_verifier_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(self.submission, None)

    def test_verifier_denial(self):
        self.verifier.allowed = False
        with self.assertRaises(TransferError):
            assess_review_submission(self.submission, self.verifier)

    def test_verifier_error_fails_closed(self):
        self.verifier.fail = True
        with self.assertRaises(TransferError):
            assess_review_submission(self.submission, self.verifier)

    def test_unexpected_truthy_result_denied(self):
        class BadVerifier:
            def verify(self, *args):
                return 1
        with self.assertRaises(TransferError):
            assess_review_submission(self.submission, BadVerifier())

    def test_bad_signature_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, signature=b"x" * 32), self.verifier,
            )

    def test_empty_signature_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, signature=b""), self.verifier,
            )

    def test_signature_too_large_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, signature=b"x" * 513), self.verifier,
            )

    def test_wrong_challenge_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, challenge=b"another-challenge-001"),
                self.verifier,
            )

    def test_short_challenge_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, challenge=b"tiny"), self.verifier,
            )

    def test_oversized_challenge_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, challenge=b"x" * 65), self.verifier,
            )

    def test_nonbytes_challenge_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, challenge="not-bytes"), self.verifier,
            )

    def test_invalid_key_id_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, reviewer_key_id="../secret"), self.verifier,
            )

    def test_empty_key_id_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, reviewer_key_id=""), self.verifier,
            )

    def test_long_key_id_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, reviewer_key_id="a" * 129), self.verifier,
            )

    def test_invalid_evidence_denied(self):
        bad = RecoveryEvidence(self.evidence.canonical_json + " ", self.evidence.sha256)
        with self.assertRaises(TransferError):
            assess_review_submission(
                replace(self.submission, evidence=bad), self.verifier,
            )

    def test_not_submission_denied(self):
        with self.assertRaises(TransferError):
            assess_review_submission({}, self.verifier)

    def test_message_changes_with_challenge(self):
        left = signing_message(self.evidence, b"1" * 16)
        right = signing_message(self.evidence, b"2" * 16)
        self.assertNotEqual(left, right)

    def test_message_changes_with_evidence(self):
        matched = build_evidence(
            RecoveryReport(RecoveryStatus.MATCH, 0, 0,
                           hashlib.sha256(b"db").hexdigest(),
                           hashlib.sha256(b"db").hexdigest()),
        )
        self.assertNotEqual(
            signing_message(self.evidence, self.challenge),
            signing_message(matched, self.challenge),
        )


if __name__ == "__main__":
    unittest.main()
