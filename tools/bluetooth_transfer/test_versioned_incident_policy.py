"""Versioned policy pin tests using two MUTABLE, NONSECURE fake sources."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anchored_challenges import EMPTY_ROOT
from fencing_incident_evidence import _build
from incident_reviewer_registry import (
    IncidentKeyPolicy, INCIDENT_SIGNER_ROLE, INCIDENT_REVIEWER_ROLE,
)
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from protocol import TransferError
from signed_fencing_incident import signing_message, attach_incident_signature
from versioned_incident_policy import (
    PolicyPin, PolicySnapshot, VersionedIncidentReviewerGate, policy_digest,
)
from witnessed_sqlite_fencing import FencingWitnessState

NS = b"j" * 32
NONCE = b"p" * 32
SIGNER = "evidence-signer"
REVIEWER = "evidence-reviewer"


class FakeSource:
    def __init__(self, value):
        self.value = value
        self.offline = False

    def read(self):
        if self.offline:
            raise OSError("source unavailable")
        return self.value


class FakePin(FakeSource):
    pass


class VersionedIncidentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        public = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        self.policies = {
            SIGNER: IncidentKeyPolicy(public, INCIDENT_SIGNER_ROLE, False, 10, 100),
            REVIEWER: IncidentKeyPolicy(other, INCIDENT_REVIEWER_ROLE, False, 10, 100),
        }
        self.now = 20
        self.snapshot = PolicySnapshot(1, dict(self.policies))
        self.source = FakeSource(self.snapshot)
        self.pin = FakePin(PolicyPin(1, policy_digest(self.snapshot)))
        self.gate = self.open()
        evidence = _build(
            NS, FencedSnapshot(NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT)),
            FencingWitnessState(NS, 0, 1, False, 0, EMPTY_ROOT), "match",
        )
        sig = self.signer.sign(signing_message(evidence, SIGNER, NONCE))
        self.signed = attach_incident_signature(evidence, SIGNER, NONCE, sig)

    def open(self):
        return VersionedIncidentReviewerGate(
            self.source, self.pin, lambda: self.now,
        )

    def refresh(self, revision, policies):
        snapshot = PolicySnapshot(revision, dict(policies))
        self.source.value = snapshot
        self.pin.value = PolicyPin(revision, policy_digest(snapshot))

    def test_pinned_signer_accepted_for_hold_only(self):
        self.assertTrue(self.gate.verify_observation(self.signed, NONCE))
        self.assertIn('"authorization":"DENY"', self.signed.evidence.canonical_json)

    def test_reviewer_only_inspects(self):
        self.assertTrue(self.gate.reviewer_can_inspect(REVIEWER))
        self.assertFalse(self.gate.reviewer_can_inspect(SIGNER))

    def test_changed_revocation_same_revision_denied(self):
        policies = dict(self.policies)
        policies[SIGNER] = replace(policies[SIGNER], revoked=True)
        self.source.value = PolicySnapshot(1, policies)
        self.assertFalse(self.gate.verify_observation(self.signed, NONCE))
        self.assertTrue(self.gate.is_held)

    def test_policy_revision_bump_blocks_old_instance(self):
        policies = dict(self.policies)
        policies[SIGNER] = replace(policies[SIGNER], revoked=True)
        self.refresh(2, policies)
        self.assertFalse(self.gate.verify_observation(self.signed, NONCE))
        self.assertFalse(self.open().verify_observation(self.signed, NONCE))

    def test_policy_revision_bump_allows_fresh_valid_reviewer(self):
        self.refresh(2, self.policies)
        self.assertFalse(self.gate.reviewer_can_inspect(REVIEWER))
        self.assertTrue(self.open().reviewer_can_inspect(REVIEWER))

    def test_new_snapshot_with_old_pin_denied(self):
        self.source.value = PolicySnapshot(2, dict(self.policies))
        with self.assertRaises(TransferError):
            self.open()

    def test_old_snapshot_with_new_pin_denied(self):
        self.pin.value = PolicyPin(2, self.pin.value.digest)
        with self.assertRaises(TransferError):
            self.open()

    def test_old_policy_rollback_after_revocation_denied(self):
        policies = dict(self.policies)
        policies[SIGNER] = replace(policies[SIGNER], revoked=True)
        self.refresh(2, policies)
        self.source.value = self.snapshot
        with self.assertRaises(TransferError):
            self.open()

    def test_outage_policy_fail_closed_sticky(self):
        self.source.offline = True
        self.assertFalse(self.gate.verify_observation(self.signed, NONCE))
        self.source.offline = False
        self.assertFalse(self.gate.verify_observation(self.signed, NONCE))

    def test_outage_pin_fail_closed_sticky(self):
        self.pin.offline = True
        self.assertFalse(self.gate.reviewer_can_inspect(REVIEWER))
        self.pin.offline = False
        self.assertFalse(self.gate.reviewer_can_inspect(REVIEWER))

    def test_missing_protected_pin_denied(self):
        with self.assertRaises(TransferError):
            VersionedIncidentReviewerGate(self.source, object(), lambda: 20)

    def test_digest_changes_for_revocation(self):
        changed = dict(self.policies)
        changed[SIGNER] = replace(changed[SIGNER], revoked=True)
        self.assertNotEqual(policy_digest(self.snapshot),
                            policy_digest(PolicySnapshot(1, changed)))

    def test_digest_changes_for_revision(self):
        self.assertNotEqual(policy_digest(self.snapshot),
                            policy_digest(PolicySnapshot(2, self.policies)))

    def test_digest_independent_of_mapping_order(self):
        shuffled = dict(reversed(list(self.policies.items())))
        self.assertEqual(policy_digest(self.snapshot),
                         policy_digest(PolicySnapshot(1, shuffled)))

    def test_boolean_revision_denied(self):
        with self.assertRaises(TransferError):
            PolicyPin(True, "a" * 64)
        with self.assertRaises(TransferError):
            PolicySnapshot(True, self.policies)

    def test_untrusted_pin_digest_denied(self):
        with self.assertRaises(TransferError):
            PolicyPin(1, "A" * 64)

    def test_empty_policy_snapshot_denied(self):
        with self.assertRaises(TransferError):
            PolicySnapshot(1, {})

    def test_wrong_nonce_denied(self):
        self.assertFalse(self.gate.verify_observation(self.signed, b"x" * 32))

    def test_expiration_checked_on_each_call(self):
        self.assertTrue(self.gate.reviewer_can_inspect(REVIEWER))
        self.now = 100
        self.assertFalse(self.gate.reviewer_can_inspect(REVIEWER))

    def test_unprotected_both_store_rollback_possible(self):
        changed = dict(self.policies)
        changed[SIGNER] = replace(changed[SIGNER], revoked=True)
        self.refresh(2, changed)
        self.source.value = self.snapshot
        self.pin.value = PolicyPin(1, policy_digest(self.snapshot))
        fresh = self.open()
        self.assertTrue(fresh.verify_observation(self.signed, NONCE))
        # This demonstrates why the pin MUST be independently protected.


if __name__ == "__main__":
    unittest.main()
