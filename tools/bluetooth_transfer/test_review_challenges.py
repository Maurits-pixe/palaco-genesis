"""Persistent challenge regressions with a fake (NOT cryptographic) verifier."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import tempfile
import unittest

from protocol import TransferError
from recovery_evidence import build_evidence
from recovery_inspection import RecoveryReport, RecoveryStatus
from review_challenges import PersistentReviewChallenges
from signed_review_gate import (
    ReviewDisposition, SignedReviewSubmission, signing_message,
)


class FakeVerifier:
    def __init__(self, approved=True):
        self.approved = approved

    def verify(self, key_id, message, signature):
        # Insecure synthetic stand-in, never use for real signature verification.
        return self.approved and signature == hashlib.sha256(message).digest()


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "challenges.sqlite"
        self.now = 1700000000
        self.clock = lambda: self.now
        self.registry = PersistentReviewChallenges(self.path, self.clock)
        self.evidence = build_evidence(RecoveryReport(
            RecoveryStatus.UNAVAILABLE, None, None, None, None,
        ))

    def make_submission(self, token, evidence=None, key="reviewer-001"):
        evidence = self.evidence if evidence is None else evidence
        return SignedReviewSubmission(
            evidence, key, token,
            hashlib.sha256(signing_message(evidence, token)).digest(),
        )

    def test_issue_length(self):
        self.assertEqual(len(self.registry.issue(self.evidence, "reviewer-001")), 32)

    def test_valid_submission_is_hold(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        result = self.registry.submit(self.make_submission(token), FakeVerifier())
        self.assertIs(result, ReviewDisposition.HOLD_REVIEWABLE)

    def test_replay_denied(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        request = self.make_submission(token)
        self.registry.submit(request, FakeVerifier())
        with self.assertRaises(TransferError):
            self.registry.submit(request, FakeVerifier())

    def test_replay_denied_after_restart(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        request = self.make_submission(token)
        self.registry.submit(request, FakeVerifier())
        reopened = PersistentReviewChallenges.reopen(self.path, self.clock)
        with self.assertRaises(TransferError):
            reopened.submit(request, FakeVerifier())

    def test_unissued_challenge_denied(self):
        with self.assertRaises(TransferError):
            self.registry.submit(self.make_submission(b"x" * 32), FakeVerifier())

    def test_expired_challenge_denied(self):
        token = self.registry.issue(self.evidence, "reviewer-001", ttl_seconds=5)
        self.now += 5
        with self.assertRaises(TransferError):
            self.registry.submit(self.make_submission(token), FakeVerifier())

    def test_before_expiration_allowed(self):
        token = self.registry.issue(self.evidence, "reviewer-001", ttl_seconds=5)
        self.now += 4
        self.assertIs(self.registry.submit(self.make_submission(token), FakeVerifier()),
                      ReviewDisposition.HOLD_REVIEWABLE)

    def test_different_reviewer_denied(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        with self.assertRaises(TransferError):
            self.registry.submit(self.make_submission(token, key="reviewer-002"), FakeVerifier())

    def test_different_evidence_denied(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        changed = build_evidence(RecoveryReport(
            RecoveryStatus.MATCH, 0, 0, "a" * 64, "a" * 64,
        ))
        with self.assertRaises(TransferError):
            self.registry.submit(self.make_submission(token, evidence=changed), FakeVerifier())

    def test_signature_denied_does_not_consume(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        request = self.make_submission(token)
        with self.assertRaises(TransferError):
            self.registry.submit(request, FakeVerifier(approved=False))
        self.assertEqual(self.registry.submit(request, FakeVerifier()),
                         ReviewDisposition.HOLD_REVIEWABLE)

    def test_invalid_signature_denied_does_not_consume(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        request = self.make_submission(token)
        with self.assertRaises(TransferError):
            self.registry.submit(replace(request, signature=b"0" * 32), FakeVerifier())
        self.assertEqual(self.registry.submit(request, FakeVerifier()),
                         ReviewDisposition.HOLD_REVIEWABLE)

    def test_simultaneous_double_submit_only_one_success(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        request = self.make_submission(token)
        second = PersistentReviewChallenges.reopen(self.path, self.clock)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(reg.submit, request, FakeVerifier())
                       for reg in (self.registry, second)]
            results = []
            for future in futures:
                try:
                    results.append(future.result())
                except TransferError:
                    results.append(None)
        self.assertEqual(results.count(ReviewDisposition.HOLD_REVIEWABLE), 1)
        self.assertEqual(results.count(None), 1)

    def test_invalid_ttl_denied(self):
        with self.assertRaises(TransferError):
            self.registry.issue(self.evidence, "reviewer-001", ttl_seconds=True)
        with self.assertRaises(TransferError):
            self.registry.issue(self.evidence, "reviewer-001", ttl_seconds=3601)

    def test_invalid_key_denied(self):
        with self.assertRaises(TransferError):
            self.registry.issue(self.evidence, "../admin")

    def test_invalid_clock_denied(self):
        self.registry._clock = lambda: False
        with self.assertRaises(TransferError):
            self.registry.issue(self.evidence, "reviewer-001")

    def test_clock_failure_denied(self):
        self.registry._clock = lambda: 1 / 0
        with self.assertRaises(TransferError):
            self.registry.issue(self.evidence, "reviewer-001")

    def test_deleted_registry_denied(self):
        token = self.registry.issue(self.evidence, "reviewer-001")
        self.path.unlink()
        with self.assertRaises(TransferError):
            self.registry.submit(self.make_submission(token), FakeVerifier())

    def test_existing_database_not_reset_by_constructor(self):
        self.registry.issue(self.evidence, "reviewer-001")
        with self.assertRaises(TransferError):
            PersistentReviewChallenges(self.path, self.clock)

    def test_reopen_missing_db_denied(self):
        missing = self.path.parent / "missing.sqlite"
        with self.assertRaises(TransferError):
            PersistentReviewChallenges.reopen(missing, self.clock)

    def test_unique_issued_challenges(self):
        a = self.registry.issue(self.evidence, "reviewer-001")
        b = self.registry.issue(self.evidence, "reviewer-001")
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
