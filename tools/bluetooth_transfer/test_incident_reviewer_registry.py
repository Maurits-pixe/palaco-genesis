"""Incident signer/reviewer policy tests. Key material ephemeral and test-only."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anchored_challenges import EMPTY_ROOT
from fencing_incident_evidence import _build
from incident_reviewer_registry import (
    IncidentKeyPolicy, IncidentReviewerRegistry,
    INCIDENT_SIGNER_ROLE, INCIDENT_REVIEWER_ROLE,
)
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from protocol import TransferError
from signed_fencing_incident import attach_incident_signature, signing_message
from witnessed_sqlite_fencing import FencingWitnessState

SCOPE = b"k" * 32
NONCE = b"q" * 32
SIGNER = "incident-signer"
REVIEWER = "incident-reviewer"


class IncidentRegistryTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        self.reviewer = Ed25519PrivateKey.generate()
        self.now = 200
        self.policy = {
            SIGNER: IncidentKeyPolicy(
                self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                INCIDENT_SIGNER_ROLE, False, 100, 300,
            ),
            REVIEWER: IncidentKeyPolicy(
                self.reviewer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                INCIDENT_REVIEWER_ROLE, False, 100, 300,
            ),
        }
        self.registry = IncidentReviewerRegistry(self.policy, lambda: self.now)
        self.evidence = _build(
            SCOPE,
            FencedSnapshot(SCOPE, 1, False, NativeCheckpoint(SCOPE, 0, EMPTY_ROOT)),
            FencingWitnessState(SCOPE, 0, 1, False, 0, EMPTY_ROOT),
            "match",
        )

    def signed(self, key=None, signer_id=SIGNER):
        private = self.signer if key is None else key
        sig = private.sign(signing_message(self.evidence, signer_id, NONCE))
        return attach_incident_signature(self.evidence, signer_id, NONCE, sig)

    def test_valid_signer_only_verifies_hold_report(self):
        self.assertTrue(self.registry.verify_observation(self.signed(), NONCE))
        self.assertIn('"authorization":"DENY"', self.evidence.canonical_json)

    def test_valid_reviewer_inspection_eligible(self):
        self.assertTrue(self.registry.reviewer_can_inspect(REVIEWER))

    def test_signer_not_reviewer(self):
        self.assertFalse(self.registry.reviewer_can_inspect(SIGNER))

    def test_reviewer_cannot_sign_as_observer(self):
        self.assertFalse(self.registry.verify_observation(
            self.signed(self.reviewer, REVIEWER), NONCE,
        ))

    def test_revoked_signer_denied(self):
        self.policy[SIGNER] = replace(self.policy[SIGNER], revoked=True)
        registry = IncidentReviewerRegistry(self.policy, lambda: self.now)
        self.assertFalse(registry.verify_observation(self.signed(), NONCE))

    def test_revoked_reviewer_denied(self):
        self.policy[REVIEWER] = replace(self.policy[REVIEWER], revoked=True)
        registry = IncidentReviewerRegistry(self.policy, lambda: self.now)
        self.assertFalse(registry.reviewer_can_inspect(REVIEWER))

    def test_policy_copy_immutable_for_existing_instance(self):
        self.policy[SIGNER] = replace(self.policy[SIGNER], revoked=True)
        self.assertTrue(self.registry.verify_observation(self.signed(), NONCE))
        # Revocation distribution is external: snapshots require secure refresh.

    def test_expired_signer_denied(self):
        self.now = 300
        self.assertFalse(self.registry.verify_observation(self.signed(), NONCE))

    def test_not_yet_valid_signer_denied(self):
        self.now = 99
        self.assertFalse(self.registry.verify_observation(self.signed(), NONCE))

    def test_expired_reviewer_denied(self):
        self.now = 300
        self.assertFalse(self.registry.reviewer_can_inspect(REVIEWER))

    def test_missing_signer_denied(self):
        registry = IncidentReviewerRegistry(
            {REVIEWER: self.policy[REVIEWER]}, lambda: self.now,
        )
        self.assertFalse(registry.verify_observation(self.signed(), NONCE))

    def test_mismatched_nonce_denied(self):
        self.assertFalse(self.registry.verify_observation(self.signed(), b"x" * 32))

    def test_wrong_signature_denied(self):
        self.assertFalse(self.registry.verify_observation(
            self.signed(self.reviewer), NONCE,
        ))

    def test_untrusted_clock_exception_denied(self):
        registry = IncidentReviewerRegistry(
            self.policy, lambda: (_ for _ in ()).throw(OSError("clock failure")),
        )
        self.assertFalse(registry.verify_observation(self.signed(), NONCE))
        self.assertFalse(registry.reviewer_can_inspect(REVIEWER))

    def test_boolean_clock_denied(self):
        registry = IncidentReviewerRegistry(self.policy, lambda: True)
        self.assertFalse(registry.verify_observation(self.signed(), NONCE))

    def test_no_key_enrollment_or_release_action(self):
        self.assertFalse(hasattr(self.registry, "enroll"))
        self.assertFalse(hasattr(self.registry, "unlock"))
        self.assertFalse(hasattr(self.registry, "authorize_recovery"))

    def test_invalid_key_policy_rejected(self):
        with self.assertRaises(TransferError):
            IncidentKeyPolicy(b"a" * 31, INCIDENT_SIGNER_ROLE, False, 1, 2)

    def test_invalid_role_rejected(self):
        with self.assertRaises(TransferError):
            IncidentKeyPolicy(b"a" * 32, "owner", False, 1, 2)

    def test_invalid_clock_window_rejected(self):
        with self.assertRaises(TransferError):
            IncidentKeyPolicy(b"a" * 32, INCIDENT_SIGNER_ROLE, False, 2, 2)

    def test_untrusted_key_shape_rejected(self):
        with self.assertRaises(TransferError):
            IncidentReviewerRegistry({"bad/key": self.policy[SIGNER]},
                                     lambda: self.now)

    def test_empty_registry_denied(self):
        with self.assertRaises(TransferError):
            IncidentReviewerRegistry({}, lambda: self.now)

    def test_changed_policy_requires_new_protected_snapshot(self):
        self.policy[SIGNER] = replace(self.policy[SIGNER], revoked=True)
        fresh = IncidentReviewerRegistry(self.policy, lambda: self.now)
        self.assertFalse(fresh.verify_observation(self.signed(), NONCE))
        self.assertTrue(self.registry.verify_observation(self.signed(), NONCE))


if __name__ == "__main__":
    unittest.main()
