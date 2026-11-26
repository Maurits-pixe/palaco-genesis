"""End-to-end native pin to signed incident review integration (fake hardware).

No trusted TPM/KeyMint driver is instantiated. Keys are ephemeral software
keys; tests prove composition and fail-closed behavior, not secure custody.
"""
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
from native_policy_custody import NativePolicyCustodyEvidence, custody_message
from native_policy_review_session import NativePolicyReviewSession
from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from publisher_rotation_gate import (
    IssuerKeyRecord, IssuerRotationSnapshot, issuer_rotation_digest,
)
from signed_fencing_incident import (
    attach_incident_signature, signing_message,
)
from signed_policy_distribution import SignedPolicyEnvelope, policy_signature_message
from versioned_incident_policy import PolicyPin, PolicySnapshot, policy_digest
from witnessed_sqlite_fencing import FencingWitnessState

NS = b"b" * 32
NONCE = b"q" * 32
ISSUER = "policy-publisher"
SIGNER = "incident-observer"
REVIEWER = "incident-reviewer"


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class Source:
    def __init__(self, value):
        self.value = value
        self.offline = False
        self.on_read = None

    def read(self):
        if self.offline:
            raise OSError("offline")
        if self.on_read:
            self.on_read()
        return self.value


class FakeNative:
    def __init__(self, key, identity, policy_pin, issuer_pin):
        self.key = key
        self.identity = identity
        self.policy_pin = policy_pin
        self.issuer_pin = issuer_pin
        self.offline = False
        self.bad_nonce = False
        self.count = 0
        self.on_attest = None

    def attest(self, challenge):
        if self.offline:
            raise OSError("hardware unavailable")
        self.count += 1
        if self.on_attest:
            self.on_attest(self.count)
        nonce = (b"x" * 32) if self.bad_nonce else challenge
        signature = self.key.sign(custody_message(
            self.identity, self.policy_pin, self.issuer_pin, nonce,
        ))
        return NativePolicyCustodyEvidence(
            self.identity, self.policy_pin, self.issuer_pin, nonce, signature,
        )


class NativePolicyReviewIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.platform = NativePlatform.WINDOWS_TPM
        self.native_key = Ed25519PrivateKey.generate()
        self.publisher_key = Ed25519PrivateKey.generate()
        self.observer_key = Ed25519PrivateKey.generate()
        self.reviewer_key = Ed25519PrivateKey.generate()
        self.identity = NativeStorageIdentity(
            self.platform, NS, b"d" * 32, 1,
        )
        self.keys = {
            SIGNER: IncidentKeyPolicy(
                pub(self.observer_key), INCIDENT_SIGNER_ROLE, False, 10, 100,
            ),
            REVIEWER: IncidentKeyPolicy(
                pub(self.reviewer_key), INCIDENT_REVIEWER_ROLE, False, 10, 100,
            ),
        }
        self.policy = PolicySnapshot(1, self.keys)
        self.issuers = IssuerRotationSnapshot(1, {
            ISSUER: IssuerKeyRecord(pub(self.publisher_key), False),
        })
        self.native = FakeNative(
            self.native_key, self.identity,
            PolicyPin(1, policy_digest(self.policy)),
            PolicyPin(1, issuer_rotation_digest(self.issuers)),
        )
        self.issuer_source = Source(self.issuers)
        self.transport = Source(self.envelope(self.policy))
        evidence = _build(
            NS,
            FencedSnapshot(NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT)),
            FencingWitnessState(NS, 0, 1, False, 0, EMPTY_ROOT),
            "match",
        )
        self.signed = attach_incident_signature(
            evidence, SIGNER, NONCE,
            self.observer_key.sign(signing_message(evidence, SIGNER, NONCE)),
        )
        self.session = self.open()

    def envelope(self, policy):
        return SignedPolicyEnvelope(
            policy, ISSUER,
            self.publisher_key.sign(policy_signature_message(policy, ISSUER)),
        )

    def open(self):
        return NativePolicyReviewSession(
            self.native, self.identity, pub(self.native_key),
            self.issuer_source, self.transport, lambda: 50,
        )

    def test_full_windows_inspection(self):
        self.assertTrue(self.session.reviewer_can_inspect(REVIEWER))
        self.assertFalse(self.session.is_held)

    def test_full_android_inspection(self):
        self.identity = replace(self.identity, platform=NativePlatform.ANDROID_KEYMINT)
        self.native.identity = self.identity
        self.assertTrue(self.open().reviewer_can_inspect(REVIEWER))

    def test_hold_only_signed_incident(self):
        self.assertTrue(self.session.verify_observation(self.signed, NONCE))
        self.assertIn('"authorization":"DENY"', self.signed.evidence.canonical_json)

    def test_signer_cannot_inspect(self):
        self.assertFalse(self.session.reviewer_can_inspect(SIGNER))

    def test_wrong_reviewer_nonce_fails(self):
        self.assertFalse(self.session.verify_observation(self.signed, b"x" * 32))

    def test_revoked_reviewer_new_policy_rejects_existing_session(self):
        new_keys = dict(self.keys)
        new_keys[REVIEWER] = replace(new_keys[REVIEWER], revoked=True)
        policy = PolicySnapshot(2, new_keys)
        self.transport.value = self.envelope(policy)
        self.native.policy_pin = PolicyPin(2, policy_digest(policy))
        self.assertFalse(self.session.reviewer_can_inspect(REVIEWER))
        self.assertTrue(self.session.is_held)

    def test_revoked_reviewer_fresh_session_denied(self):
        new_keys = dict(self.keys)
        new_keys[REVIEWER] = replace(new_keys[REVIEWER], revoked=True)
        policy = PolicySnapshot(2, new_keys)
        self.transport.value = self.envelope(policy)
        self.native.policy_pin = PolicyPin(2, policy_digest(policy))
        self.assertFalse(self.open().reviewer_can_inspect(REVIEWER))

    def test_issuer_revoked_deny_fresh_session(self):
        issuers = IssuerRotationSnapshot(2, {
            ISSUER: replace(self.issuers.keys[ISSUER], revoked=True),
        })
        self.issuer_source.value = issuers
        self.native.issuer_pin = PolicyPin(2, issuer_rotation_digest(issuers))
        with self.assertRaises(TransferError):
            self.open()

    def test_policy_replay_with_advanced_pin_denied(self):
        self.native.policy_pin = PolicyPin(2, "a" * 64)
        with self.assertRaises(TransferError):
            self.open()

    def test_issuer_pin_and_registry_divergence_denied(self):
        self.native.issuer_pin = PolicyPin(2, "a" * 64)
        with self.assertRaises(TransferError):
            self.open()

    def test_device_swap_denied(self):
        self.native.identity = replace(self.identity, device_binding=b"z" * 32)
        self.assertFalse(self.session.reviewer_can_inspect(REVIEWER))
        self.assertTrue(self.session.is_held)

    def test_stale_attestation_challenge_denied(self):
        self.native.bad_nonce = True
        self.assertFalse(self.session.reviewer_can_inspect(REVIEWER))

    def test_native_outage_is_sticky(self):
        self.native.offline = True
        self.assertFalse(self.session.verify_observation(self.signed, NONCE))
        self.native.offline = False
        self.assertFalse(self.session.verify_observation(self.signed, NONCE))
        self.assertTrue(self.session.is_held)

    def test_signed_transport_failure_denied(self):
        self.transport.offline = True
        self.assertFalse(self.session.reviewer_can_inspect(REVIEWER))
        self.assertTrue(self.session.is_held)

    def test_issuer_registry_failure_denied(self):
        self.issuer_source.offline = True
        self.assertFalse(self.session.reviewer_can_inspect(REVIEWER))

    def test_change_during_review_denied(self):
        def change_pin(count):
            if count == self.native.count + 1:
                self.native.policy_pin = PolicyPin(2, "a" * 64)
        # Snapshot count is monotone, but this is a deliberately injected
        # change triggered at the next native attestation.
        next_read = self.native.count + 1
        self.native.on_attest = lambda count: (
            setattr(self.native, "policy_pin", PolicyPin(2, "a" * 64))
            if count == next_read else None
        )
        self.assertFalse(self.session.reviewer_can_inspect(REVIEWER))
        self.assertTrue(self.session.is_held)

    def test_review_does_not_advance_native_pins(self):
        before = (self.native.policy_pin, self.native.issuer_pin)
        self.session.reviewer_can_inspect(REVIEWER)
        self.session.verify_observation(self.signed, NONCE)
        self.assertEqual(before, (self.native.policy_pin, self.native.issuer_pin))

    def test_no_privileged_authorization_methods(self):
        for action in ("unlock", "release", "import_records", "recover",
                       "advance", "deploy", "enroll_key"):
            self.assertFalse(hasattr(self.session, action))

    def test_fake_native_signature_is_not_hardware_attestation(self):
        self.assertTrue(self.session.reviewer_can_inspect(REVIEWER))
        self.assertFalse(hasattr(self.native, "tpm_driver"))

    def test_wrong_attestation_key_rejected(self):
        with self.assertRaises(TransferError):
            NativePolicyReviewSession(
                self.native, self.identity, pub(Ed25519PrivateKey.generate()),
                self.issuer_source, self.transport, lambda: 50,
            )


if __name__ == "__main__":
    unittest.main()
