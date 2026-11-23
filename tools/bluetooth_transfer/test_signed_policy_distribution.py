"""Signed policy delivery regressions with ephemeral test-only Ed25519 keys."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from incident_reviewer_registry import (
    IncidentKeyPolicy, INCIDENT_SIGNER_ROLE, INCIDENT_REVIEWER_ROLE,
)
from protocol import TransferError
from signed_policy_distribution import (
    SignedPolicyEnvelope, VerifiedSignedPolicySource,
    policy_signature_message,
)
from versioned_incident_policy import (
    PolicyPin, PolicySnapshot, VersionedIncidentReviewerGate, policy_digest,
)

ISSUER = "palaco-policy-publisher"
SIGNER = "incident-signer"
REVIEWER = "incident-reviewer"


class FakeTransport:
    def __init__(self, envelope):
        self.envelope = envelope
        self.offline = False

    def read(self):
        if self.offline:
            raise OSError("unavailable")
        return self.envelope


class FakePin:
    def __init__(self, policy):
        self.value = PolicyPin(policy.revision, policy_digest(policy))

    def read(self):
        return self.value


class SignedPolicyDistributionTests(unittest.TestCase):
    def setUp(self):
        self.issuer = Ed25519PrivateKey.generate()
        self.other_issuer = Ed25519PrivateKey.generate()
        self.pub = self.issuer.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        self.signer = Ed25519PrivateKey.generate()
        self.keys = {
            SIGNER: IncidentKeyPolicy(
                self.signer.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw,
                ), INCIDENT_SIGNER_ROLE, False, 1, 1000,
            ),
            REVIEWER: IncidentKeyPolicy(
                Ed25519PrivateKey.generate().public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw,
                ), INCIDENT_REVIEWER_ROLE, False, 1, 1000,
            ),
        }
        self.policy = PolicySnapshot(1, dict(self.keys))
        self.transport = FakeTransport(self.envelope(self.policy))
        self.source = VerifiedSignedPolicySource(
            self.transport, {ISSUER: self.pub},
        )
        self.pin = FakePin(self.policy)

    def envelope(self, policy, private=None, issuer_id=ISSUER):
        key = self.issuer if private is None else private
        return SignedPolicyEnvelope(
            policy, issuer_id, key.sign(
                policy_signature_message(policy, issuer_id),
            ),
        )

    def gate(self):
        return VersionedIncidentReviewerGate(
            self.source, self.pin, lambda: 50,
        )

    def test_verified_source_returns_matching_policy(self):
        result = self.source.read()
        self.assertEqual(policy_digest(result), policy_digest(self.policy))

    def test_signed_source_integrates_with_pinned_gate(self):
        self.assertTrue(self.gate().reviewer_can_inspect(REVIEWER))

    def test_signed_policy_still_only_inspection(self):
        gate = self.gate()
        self.assertFalse(gate.reviewer_can_inspect(SIGNER))
        self.assertFalse(hasattr(gate, "release"))
        self.assertFalse(hasattr(gate, "unlock"))

    def test_changed_revocation_with_old_signature_denied(self):
        revised = dict(self.keys)
        revised[SIGNER] = replace(revised[SIGNER], revoked=True)
        self.transport.envelope = replace(
            self.transport.envelope, policy=PolicySnapshot(1, revised),
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_changed_role_with_old_signature_denied(self):
        revised = dict(self.keys)
        revised[REVIEWER] = replace(
            revised[REVIEWER], role=INCIDENT_SIGNER_ROLE,
        )
        self.transport.envelope = replace(
            self.transport.envelope, policy=PolicySnapshot(1, revised),
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_wrong_publisher_signature_denied(self):
        self.transport.envelope = self.envelope(
            self.policy, private=self.other_issuer,
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_unknown_publisher_id_denied(self):
        self.transport.envelope = self.envelope(
            self.policy, issuer_id="unexpected-issuer",
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_publisher_identity_substitution_denied(self):
        self.transport.envelope = replace(
            self.transport.envelope, issuer_key_id="unexpected-issuer",
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_signature_bitflip_denied(self):
        envelope = self.transport.envelope
        signature = bytearray(envelope.signature)
        signature[0] ^= 1
        self.transport.envelope = replace(
            envelope, signature=bytes(signature),
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_policy_revision_tamper_denied(self):
        self.transport.envelope = replace(
            self.transport.envelope,
            policy=PolicySnapshot(2, dict(self.keys)),
        )
        with self.assertRaises(TransferError):
            self.source.read()

    def test_replayed_old_signed_policy_fails_new_pin(self):
        revised = dict(self.keys)
        revised[SIGNER] = replace(revised[SIGNER], revoked=True)
        new_policy = PolicySnapshot(2, revised)
        self.pin.value = PolicyPin(2, policy_digest(new_policy))
        with self.assertRaises(TransferError):
            self.gate()  # valid old signature is insufficient

    def test_new_signed_policy_accepted_after_pin_update(self):
        new_policy = PolicySnapshot(2, dict(self.keys))
        self.transport.envelope = self.envelope(new_policy)
        self.pin.value = PolicyPin(2, policy_digest(new_policy))
        self.assertTrue(self.gate().reviewer_can_inspect(REVIEWER))

    def test_changed_policy_without_new_pin_denied(self):
        new_policy = PolicySnapshot(2, dict(self.keys))
        self.transport.envelope = self.envelope(new_policy)
        with self.assertRaises(TransferError):
            self.gate()

    def test_existing_gate_denies_update_even_if_signed(self):
        gate = self.gate()
        new_policy = PolicySnapshot(2, dict(self.keys))
        self.transport.envelope = self.envelope(new_policy)
        self.pin.value = PolicyPin(2, policy_digest(new_policy))
        self.assertFalse(gate.reviewer_can_inspect(REVIEWER))
        self.assertTrue(gate.is_held)

    def test_signed_transport_outage_denied(self):
        gate = self.gate()
        self.transport.offline = True
        self.assertFalse(gate.reviewer_can_inspect(REVIEWER))
        self.assertTrue(gate.is_held)

    def test_invalid_transport_envelope_denied(self):
        self.transport.envelope = {"signed": "fake"}
        with self.assertRaises(TransferError):
            self.source.read()

    def test_invalid_publisher_pinset_denied(self):
        with self.assertRaises(TransferError):
            VerifiedSignedPolicySource(
                self.transport, {ISSUER: b"not-a-public-key"},
            )

    def test_invalid_envelope_signature_size_denied(self):
        with self.assertRaises(TransferError):
            SignedPolicyEnvelope(self.policy, ISSUER, b"short")

    def test_untrusted_both_policy_and_pin_rollback_still_possible(self):
        new_policy = PolicySnapshot(2, dict(self.keys))
        self.transport.envelope = self.envelope(new_policy)
        self.pin.value = PolicyPin(2, policy_digest(new_policy))
        self.assertTrue(self.gate().reviewer_can_inspect(REVIEWER))
        self.transport.envelope = self.envelope(self.policy)
        self.pin.value = PolicyPin(1, policy_digest(self.policy))
        self.assertTrue(self.gate().reviewer_can_inspect(REVIEWER))
        # Protection requires genuine monotonic pin outside adversary control.

    def test_policy_copy_not_mutated_after_verified_read(self):
        output = self.source.read()
        self.keys[SIGNER] = replace(self.keys[SIGNER], revoked=True)
        self.assertFalse(output.keys[SIGNER].revoked)
        with self.assertRaises(TypeError):
            output.keys[SIGNER] = self.keys[SIGNER]


if __name__ == "__main__":
    unittest.main()
