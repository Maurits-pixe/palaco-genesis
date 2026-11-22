"""End-to-end synthetic offline review intake, genuine Ed25519 signatures."""
from dataclasses import replace
import tempfile
from pathlib import Path
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ed25519_review_verifier import REVIEW_ROLE, ReviewerPublicKey
from protected_policy_gate import PinnedPolicyState
from protocol import TransferError
from recovery_evidence import build_evidence
from recovery_inspection import RecoveryReport, RecoveryStatus
from review_intake import RecoveryReviewIntake
from signed_review_gate import (
    ReviewDisposition, SignedReviewSubmission, signing_message,
)
from signed_reviewer_policy import (
    DOMAIN, SignedReviewerPolicy, canonical_policy,
)


def raw_public(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


class MutableAnchor:
    """Unprotected test stub; not a production trusted root."""

    def __init__(self, root):
        self.state = PinnedPolicyState(raw_public(root), 1)
        self.fail = False
        self.read_count = 0
        self.on_read = None

    def read(self):
        self.read_count += 1
        if self.fail:
            raise OSError("anchor unavailable")
        if self.on_read is not None:
            self.on_read(self.read_count)
        return self.state


class EndToEndReviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "challenges.sqlite"
        self.root = Ed25519PrivateKey.generate()
        self.reviewer = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        self.anchor = MutableAnchor(self.root)
        self.now = 150
        self.clock = lambda: self.now
        self.entry = ReviewerPublicKey(
            raw_public(self.reviewer), REVIEW_ROLE, False, 100, 10000,
        )
        self.policy = self.sign_policy(1, {"reviewer": self.entry})
        self.evidence = build_evidence(
            RecoveryReport(RecoveryStatus.UNAVAILABLE, None, None, None, None),
        )

    def sign_policy(self, version, keys):
        raw = canonical_policy(version, keys)
        return SignedReviewerPolicy(
            raw, self.root.sign(DOMAIN + raw.encode("ascii")),
        )

    def intake(self, *, create=False, policy=None):
        return RecoveryReviewIntake(
            self.policy if policy is None else policy,
            self.anchor, self.clock, self.path, create_new_registry=create,
        )

    def signed(self, challenge, *, private=None, key_id="reviewer", evidence=None):
        evidence = self.evidence if evidence is None else evidence
        private = self.reviewer if private is None else private
        return SignedReviewSubmission(
            evidence, key_id, challenge,
            private.sign(signing_message(evidence, challenge)),
        )

    def test_full_flow_is_hold(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.assertIs(
            intake.submit(self.signed(token)),
            ReviewDisposition.HOLD_REVIEWABLE,
        )

    def test_replay_after_success_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        request = self.signed(token)
        intake.submit(request)
        with self.assertRaises(TransferError):
            intake.submit(request)

    def test_replay_after_restart_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        request = self.signed(token)
        intake.submit(request)
        with self.assertRaises(TransferError):
            self.intake().submit(request)

    def test_real_wrong_private_key_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token, private=self.other))
        self.assertIs(
            intake.submit(self.signed(token)), ReviewDisposition.HOLD_REVIEWABLE,
        )

    def test_revoked_reviewer_denied(self):
        policy = self.sign_policy(1, {
            "reviewer": replace(self.entry, revoked=True),
        })
        intake = self.intake(create=True, policy=policy)
        token = intake.issue_challenge(self.evidence, "reviewer")
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_wrong_role_denied(self):
        policy = self.sign_policy(1, {
            "reviewer": replace(self.entry, role="observer"),
        })
        intake = self.intake(create=True, policy=policy)
        token = intake.issue_challenge(self.evidence, "reviewer")
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_expired_challenge_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.now += 300
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_expired_reviewer_key_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.now = 10000
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_root_rotation_after_issue_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.anchor.state = PinnedPolicyState(raw_public(self.other), 1)
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_policy_revision_after_issue_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.anchor.state = replace(self.anchor.state, revision=2)
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_revision_rollback_at_start_denied(self):
        self.anchor.state = replace(self.anchor.state, revision=2)
        with self.assertRaises(TransferError):
            self.intake(create=True)

    def test_missing_anchor_at_submit_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        self.anchor.fail = True
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_tampered_evidence_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        other = build_evidence(
            RecoveryReport(RecoveryStatus.MATCH, 0, 0, "a" * 64, "a" * 64),
        )
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token, evidence=other))

    def test_different_reviewer_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token, key_id="other"))

    def test_parallel_duplicate_only_one(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        request = self.signed(token)
        second = self.intake()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(item.submit, request) for item in (intake, second)]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result())
                except TransferError:
                    outcomes.append(None)
        self.assertEqual(outcomes.count(ReviewDisposition.HOLD_REVIEWABLE), 1)
        self.assertEqual(outcomes.count(None), 1)

    def test_missing_registry_denied_without_creating(self):
        with self.assertRaises(TransferError):
            self.intake()
        self.assertFalse(self.path.exists())

    def test_double_initialization_denied(self):
        self.intake(create=True)
        with self.assertRaises(TransferError):
            self.intake(create=True)

    def test_wrong_issuer_signature_denied(self):
        raw = self.policy.canonical_json
        forged = SignedReviewerPolicy(
            raw, self.other.sign(DOMAIN + raw.encode("ascii")),
        )
        with self.assertRaises(TransferError):
            self.intake(create=True, policy=forged)

    def test_anchor_changed_during_signature_denied(self):
        intake = self.intake(create=True)
        token = intake.issue_challenge(self.evidence, "reviewer")
        before = self.anchor.read_count

        def change_on_second_read(count):
            if count == before + 2:
                self.anchor.state = replace(self.anchor.state, revision=2)

        self.anchor.on_read = change_on_second_read
        with self.assertRaises(TransferError):
            intake.submit(self.signed(token))

    def test_no_external_authority_granted(self):
        intake = self.intake(create=True)
        result = intake.submit(self.signed(
            intake.issue_challenge(self.evidence, "reviewer"),
        ))
        self.assertEqual(result.value, "hold_reviewable")
        self.assertFalse(hasattr(intake, "repair"))
        self.assertFalse(hasattr(intake, "import_data"))


if __name__ == "__main__":
    unittest.main()
