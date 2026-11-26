"""Hardened review intake integration tests with ephemeral Ed25519 keys.

External anchor here is only a fake: no anti-rollback hardware is provided.
"""
from dataclasses import replace
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anchored_challenges import EMPTY_ROOT
from ed25519_review_verifier import ReviewerPublicKey, REVIEW_ROLE
from protected_policy_gate import PinnedPolicyState
from protocol import TransferError
from recovery_evidence import build_evidence
from recovery_inspection import RecoveryReport, RecoveryStatus
from review_intake import AnchoredRecoveryReviewIntake
from signed_review_gate import ReviewDisposition, SignedReviewSubmission, signing_message
from signed_reviewer_policy import DOMAIN, SignedReviewerPolicy, canonical_policy


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


class PolicyAnchor:
    def __init__(self, root):
        self.state = PinnedPolicyState(pub(root), 1)
        self.offline = False

    def read(self):
        if self.offline:
            raise OSError("missing")
        return self.state


class LedgerAnchor:
    def __init__(self):
        self.state = (0, EMPTY_ROOT)
        self.lock = threading.Lock()
        self.offline = False
        self.uncertain_advance = False

    def read(self):
        with self.lock:
            if self.offline:
                raise OSError("missing")
            return self.state

    def advance(self, before, after):
        with self.lock:
            if self.offline or before != self.state:
                raise OSError("CAS unavailable")
            self.state = after
            if self.uncertain_advance:
                raise OSError("uncertain write")


class AnchoredIntakeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "review.sqlite"
        self.root = Ed25519PrivateKey.generate()
        self.reviewer = Ed25519PrivateKey.generate()
        self.policy_anchor = PolicyAnchor(self.root)
        self.ledger_anchor = LedgerAnchor()
        self.now = 150
        self.clock = lambda: self.now
        entry = ReviewerPublicKey(pub(self.reviewer), REVIEW_ROLE, False, 100, 900)
        raw = canonical_policy(1, {"reviewer": entry})
        self.policy = SignedReviewerPolicy(
            raw, self.root.sign(DOMAIN + raw.encode("ascii")),
        )
        self.evidence = build_evidence(
            RecoveryReport(RecoveryStatus.UNAVAILABLE, None, None, None, None),
        )

    def intake(self, create=False, ledger_anchor=None):
        return AnchoredRecoveryReviewIntake(
            self.policy, self.policy_anchor, self.clock,
            self.path, self.ledger_anchor if ledger_anchor is None else ledger_anchor,
            create_new_registry=create,
        )

    def signed(self, token, private=None):
        private = self.reviewer if private is None else private
        return SignedReviewSubmission(
            self.evidence, "reviewer", token,
            private.sign(signing_message(self.evidence, token)),
        )

    def test_real_ed25519_and_anchored_ledger(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.assertEqual(self.ledger_anchor.state[0], 1)
        before = self.ledger_anchor.state
        self.assertIs(intake.submit(self.signed(token)), ReviewDisposition.HOLD_REVIEWABLE)
        self.assertEqual(self.ledger_anchor.state[0], 1)
        self.assertNotEqual(self.ledger_anchor.state, before)

    def test_replay_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        intake.submit(self.signed(token))
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_replay_after_restart_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        intake.submit(self.signed(token))
        with self.assertRaises(TransferError):
            self.intake().submit(self.signed(token))

    def test_no_legacy_fallback_when_anchor_missing(self):
        with self.assertRaises(TransferError):
            self.intake(create=True, ledger_anchor=object())
        self.assertFalse(self.path.exists())

    def test_missing_ledger_refuses_default_reopen(self):
        with self.assertRaises(TransferError):
            self.intake()
        self.assertFalse(self.path.exists())

    def test_existing_db_cannot_be_reinitialized(self):
        self.intake(create=True)
        with self.assertRaises(TransferError):
            self.intake(create=True)

    def test_ledger_anchor_unavailable_at_start(self):
        self.ledger_anchor.offline = True
        with self.assertRaises(TransferError):
            self.intake(create=True)

    def test_ledger_anchor_unavailable_on_issue(self):
        intake = self.intake(create=True)
        self.ledger_anchor.offline = True
        with self.assertRaises(TransferError):
            intake.issue_challenge(self.evidence, "reviewer")

    def test_ledger_anchor_unavailable_on_submit(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.ledger_anchor.offline = True
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_consumed_flag_rollback_denied(self):
        import sqlite3
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        intake.submit(self.signed(token))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE challenges SET consumed=0 WHERE token=?", (token,))
        with self.assertRaises(TransferError):
            self.intake()

    def test_wrong_private_key_denied_then_valid(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token, Ed25519PrivateKey.generate()))
        self.assertIs(intake.submit(self.signed(token)), ReviewDisposition.HOLD_REVIEWABLE)

    def test_policy_rotation_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.policy_anchor.state = replace(self.policy_anchor.state, revision=2)
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_expired_challenge_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.now += 300
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_uncertain_anchor_advance_produces_hold(self):
        intake = self.intake(create=True)
        self.ledger_anchor.uncertain_advance = True
        with self.assertRaises(TransferError):
            intake.issue_challenge(self.evidence, "reviewer")
        with self.assertRaises(TransferError):
            self.intake()

    def test_concurrent_double_submit(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        request = self.signed(token)
        second = self.intake()
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(candidate.submit, request)
                    for candidate in (intake, second)]
            outcomes = []
            for job in jobs:
                try:
                    outcomes.append(job.result())
                except TransferError:
                    outcomes.append(None)
        self.assertEqual(outcomes.count(ReviewDisposition.HOLD_REVIEWABLE), 1)
        self.assertEqual(outcomes.count(None), 1)

    def test_no_repair_or_import_authority(self):
        intake = self.intake(create=True)
        self.assertFalse(hasattr(intake, "repair"))
        self.assertFalse(hasattr(intake, "import_data"))


if __name__ == "__main__":
    unittest.main()
