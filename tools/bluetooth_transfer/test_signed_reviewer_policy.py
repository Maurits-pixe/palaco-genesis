"""Real Ed25519 root-signed offline reviewer policy regressions."""
from dataclasses import replace
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ed25519_review_verifier import ReviewerPublicKey, REVIEW_ROLE
from protocol import TransferError
from signed_reviewer_policy import (
    DOMAIN, SignedReviewerPolicy, canonical_policy, load_signed_policy,
)


def raw_public(private):
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class SignedReviewerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = Ed25519PrivateKey.generate()
        self.reviewer = Ed25519PrivateKey.generate()
        self.other_root = Ed25519PrivateKey.generate()
        self.review_key = ReviewerPublicKey(
            raw_public(self.reviewer), REVIEW_ROLE, False, 100, 200,
        )
        self.keys = {"reviewer-1": self.review_key}
        self.expected = 7
        self.now = 150
        self.json = canonical_policy(self.expected, self.keys)
        self.bundle = self.sign(self.json)

    def sign(self, raw):
        return SignedReviewerPolicy(raw, self.root.sign(DOMAIN + raw.encode("ascii")))

    def load(self, bundle=None, root=None, revision=None):
        return load_signed_policy(
            self.bundle if bundle is None else bundle,
            raw_public(self.root) if root is None else root,
            self.expected if revision is None else revision,
            lambda: self.now,
        )

    def test_valid_policy_verifies_real_reviewer(self):
        verifier = self.load()
        message = b"review-domain-bound-message"
        self.assertTrue(verifier.verify(
            "reviewer-1", message, self.reviewer.sign(message),
        ))

    def test_wrong_root_rejected(self):
        with self.assertRaises(TransferError):
            self.load(root=raw_public(self.other_root))

    def test_tampered_signature_rejected(self):
        with self.assertRaises(TransferError):
            self.load(bundle=replace(self.bundle, signature=b"0" * 64))

    def test_modified_roster_rejected(self):
        changed = canonical_policy(
            7, {"reviewer-1": replace(self.review_key, revoked=True)}
        )
        with self.assertRaises(TransferError):
            self.load(bundle=replace(self.bundle, canonical_json=changed))

    def test_old_policy_revision_rejected(self):
        with self.assertRaises(TransferError):
            self.load(revision=8)

    def test_wrong_expected_version_rejected(self):
        with self.assertRaises(TransferError):
            self.load(revision=6)

    def test_root_signed_revocation_denies_reviewer(self):
        revoked = self.sign(canonical_policy(
            8, {"reviewer-1": replace(self.review_key, revoked=True)}
        ))
        verifier = self.load(bundle=revoked, revision=8)
        self.assertFalse(verifier.verify(
            "reviewer-1", b"message", self.reviewer.sign(b"message"),
        ))

    def test_old_signed_policy_cannot_bypass_revocation(self):
        with self.assertRaises(TransferError):
            self.load(self.bundle, revision=8)

    def test_wrong_role_denied(self):
        bad_role = self.sign(canonical_policy(
            7, {"reviewer-1": replace(self.review_key, role="observer")}
        ))
        verifier = self.load(bundle=bad_role)
        self.assertFalse(verifier.verify(
            "reviewer-1", b"message", self.reviewer.sign(b"message"),
        ))

    def test_clock_outside_window_denied(self):
        self.now = 200
        verifier = self.load()
        self.assertFalse(verifier.verify(
            "reviewer-1", b"message", self.reviewer.sign(b"message"),
        ))

    def test_unknown_reviewer_denied(self):
        verifier = self.load()
        self.assertFalse(verifier.verify(
            "unknown", b"message", self.reviewer.sign(b"message"),
        ))

    def test_noncanonical_whitespace_denied(self):
        with self.assertRaises(TransferError):
            self.load(bundle=self.sign(self.json + " "))

    def test_duplicate_json_field_denied(self):
        raw = self.json[:-1] + ',"revision":7}'
        with self.assertRaises(TransferError):
            self.load(bundle=self.sign(raw))

    def test_unknown_policy_field_denied(self):
        doc = json.loads(self.json)
        doc["allow_import"] = True
        with self.assertRaises(TransferError):
            self.load(bundle=self.sign(json.dumps(doc, sort_keys=True, separators=(",", ":"))))

    def test_unknown_key_attribute_denied(self):
        doc = json.loads(self.json)
        doc["reviewers"]["reviewer-1"]["administrator"] = True
        with self.assertRaises(TransferError):
            self.load(bundle=self.sign(json.dumps(doc, sort_keys=True, separators=(",", ":"))))

    def test_invalid_public_key_hex_denied(self):
        doc = json.loads(self.json)
        doc["reviewers"]["reviewer-1"]["public_key"] = "z" * 64
        with self.assertRaises(TransferError):
            self.load(bundle=self.sign(json.dumps(doc, sort_keys=True, separators=(",", ":"))))

    def test_empty_policy_denied(self):
        with self.assertRaises(TransferError):
            canonical_policy(7, {})

    def test_invalid_revision_type_denied(self):
        with self.assertRaises(TransferError):
            canonical_policy(True, self.keys)

    def test_missing_pinned_root_denied(self):
        with self.assertRaises(TransferError):
            self.load(root=b"")

    def test_missing_clock_denied(self):
        with self.assertRaises(TransferError):
            load_signed_policy(self.bundle, raw_public(self.root), 7, None)

    def test_forged_bundle_rejected(self):
        with self.assertRaises(TransferError):
            self.load(bundle=SignedReviewerPolicy(self.json, b"x" * 64))

    def test_canonical_stable(self):
        self.assertEqual(self.json, canonical_policy(7, self.keys))

    def test_max_policy_size_rejected(self):
        with self.assertRaises(TransferError):
            self.load(bundle=SignedReviewerPolicy(self.json + " " * 65536, b"x" * 64))

    def test_new_revision_allows_key_rotation(self):
        replacement = Ed25519PrivateKey.generate()
        new_policy = self.sign(canonical_policy(
            8, {"reviewer-2": ReviewerPublicKey(
                raw_public(replacement), REVIEW_ROLE, False, 100, 200,
            )}
        ))
        verifier = self.load(bundle=new_policy, revision=8)
        msg = b"next"
        self.assertTrue(verifier.verify("reviewer-2", msg, replacement.sign(msg)))
        self.assertFalse(verifier.verify("reviewer-1", msg, self.reviewer.sign(msg)))


if __name__ == "__main__":
    unittest.main()
