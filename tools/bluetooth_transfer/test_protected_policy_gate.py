"""Anchor-change denial regressions with synthetic untrusted test anchor."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ed25519_review_verifier import ReviewerPublicKey, REVIEW_ROLE
from protected_policy_gate import (
    AnchoredReviewVerifier, PinnedPolicyState,
)
from protocol import TransferError
from signed_reviewer_policy import (
    DOMAIN, SignedReviewerPolicy, canonical_policy,
)


def public_bytes(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


class FakeAnchor:
    """Test stub only; does not provide protected storage or anti-rollback."""

    def __init__(self, state):
        self.state = state
        self.offline = False

    def read(self):
        if self.offline:
            raise OSError("anchor offline")
        return self.state


class ProtectedPolicyGateTests(unittest.TestCase):
    def setUp(self):
        self.root = Ed25519PrivateKey.generate()
        self.other_root = Ed25519PrivateKey.generate()
        self.reviewer = Ed25519PrivateKey.generate()
        self.state = PinnedPolicyState(public_bytes(self.root), 3)
        self.anchor = FakeAnchor(self.state)
        self.now = 150
        self.clock = lambda: self.now
        self.message = b"reviewer-verified-message"
        self.signature = self.reviewer.sign(self.message)
        entry = ReviewerPublicKey(
            public_bytes(self.reviewer), REVIEW_ROLE, False, 100, 200,
        )
        raw = canonical_policy(3, {"reviewer": entry})
        self.policy = SignedReviewerPolicy(
            raw, self.root.sign(DOMAIN + raw.encode("ascii")),
        )

    def verifier(self):
        return AnchoredReviewVerifier(self.policy, self.anchor, self.clock)

    def check(self, verifier):
        return verifier.verify("reviewer", self.message, self.signature)

    def test_accepts_valid_genuine_signature(self):
        self.assertTrue(self.check(self.verifier()))

    def test_revision_advances_after_load_denied(self):
        verifier = self.verifier()
        self.anchor.state = replace(self.state, revision=4)
        self.assertFalse(self.check(verifier))

    def test_revision_rollback_after_load_denied(self):
        verifier = self.verifier()
        self.anchor.state = replace(self.state, revision=2)
        self.assertFalse(self.check(verifier))

    def test_rotated_root_after_load_denied(self):
        verifier = self.verifier()
        self.anchor.state = replace(
            self.state, root_public_key=public_bytes(self.other_root),
        )
        self.assertFalse(self.check(verifier))

    def test_anchor_unavailable_after_load_denied(self):
        verifier = self.verifier()
        self.anchor.offline = True
        self.assertFalse(self.check(verifier))

    def test_anchor_missing_at_construction_denied(self):
        self.anchor.offline = True
        with self.assertRaises(TransferError):
            self.verifier()

    def test_anchor_missing_reader_denied(self):
        with self.assertRaises(TransferError):
            AnchoredReviewVerifier(self.policy, object(), self.clock)

    def test_anchor_wrong_return_type_denied(self):
        self.anchor.state = (public_bytes(self.root), 3)
        with self.assertRaises(TransferError):
            self.verifier()

    def test_old_policy_rejected_after_revision_change(self):
        self.anchor.state = replace(self.state, revision=4)
        with self.assertRaises(TransferError):
            self.verifier()

    def test_wrong_root_rejected_at_load(self):
        self.anchor.state = replace(
            self.state, root_public_key=public_bytes(self.other_root),
        )
        with self.assertRaises(TransferError):
            self.verifier()

    def test_wrong_signature_denied(self):
        self.assertFalse(self.verifier().verify(
            "reviewer", self.message, self.other_root.sign(self.message),
        ))

    def test_unknown_reviewer_denied(self):
        self.assertFalse(self.verifier().verify(
            "untrusted", self.message, self.signature,
        ))

    def test_expired_reviewer_denied(self):
        verifier = self.verifier()
        self.now = 200
        self.assertFalse(self.check(verifier))

    def test_bad_clock_denied(self):
        verifier = self.verifier()
        self.now = True
        self.assertFalse(self.check(verifier))

    def test_invalid_pinned_key_rejected(self):
        with self.assertRaises(TransferError):
            PinnedPolicyState(b"short", 3)

    def test_boolean_revision_rejected(self):
        with self.assertRaises(TransferError):
            PinnedPolicyState(public_bytes(self.root), True)

    def test_revision_zero_rejected(self):
        with self.assertRaises(TransferError):
            PinnedPolicyState(public_bytes(self.root), 0)

    def test_changed_anchor_restore_succeeds_not_anti_rollback(self):
        verifier = self.verifier()
        self.anchor.state = replace(self.state, revision=4)
        self.assertFalse(self.check(verifier))
        # This proves the limit: reverting the anchor fake to its old value
        # defeats this in-process guard. A real secure anchor MUST prevent it.
        self.anchor.state = self.state
        self.assertTrue(self.check(verifier))


if __name__ == "__main__":
    unittest.main()
