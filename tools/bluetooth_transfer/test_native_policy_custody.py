"""Native policy custody tests use a fake signer: NO TPM/KeyMint evidence."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from native_policy_custody import (
    AttestedNativePolicyPins, NativePolicyCustodyEvidence,
    bind_native_policy_pin_views, custody_message,
)
from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from versioned_incident_policy import PolicyPin

NS = b"z" * 32
DEVICE = b"d" * 32
PIN1 = PolicyPin(1, "a" * 64)
PIN2 = PolicyPin(2, "b" * 64)


class FakeNative:
    def __init__(self, key, identity):
        self.key = key
        self.identity = identity
        self.policy = PIN1
        self.issuer = PIN2
        self.stale = None
        self.corrupt = False
        self.outage = False

    def attest(self, challenge):
        if self.outage:
            raise OSError("native disconnected")
        if self.stale is not None:
            challenge = self.stale
        signature = self.key.sign(custody_message(
            self.identity, self.policy, self.issuer, challenge,
        ))
        if self.corrupt:
            signature = b"x" + signature[1:]
        return NativePolicyCustodyEvidence(
            self.identity, self.policy, self.issuer, challenge, signature,
        )


class NativePolicyCustodyTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        self.identity = NativeStorageIdentity(
            NativePlatform.WINDOWS_TPM, NS, DEVICE, 1,
        )
        self.native = FakeNative(self.key, self.identity)

    def open(self):
        return AttestedNativePolicyPins(
            self.native, self.identity, self.public,
        )

    def test_valid_windows_challenged_pins(self):
        gate = self.open()
        self.assertEqual(gate.read_pair(), (PIN1, PIN2))
        self.assertFalse(gate.is_held)

    def test_android_keymint_platform_is_explicit(self):
        self.identity = NativeStorageIdentity(
            NativePlatform.ANDROID_KEYMINT, NS, DEVICE, 1,
        )
        self.native.identity = self.identity
        self.assertEqual(self.open().policy_pin(), PIN1)

    def test_two_readonly_views(self):
        custody, policy, issuer = bind_native_policy_pin_views(
            self.native, self.identity, self.public,
        )
        self.assertEqual(policy.read(), PIN1)
        self.assertEqual(issuer.read(), PIN2)
        self.assertFalse(hasattr(custody, "advance"))

    def test_native_policy_change_latches_hold(self):
        gate = self.open()
        self.native.policy = PolicyPin(2, "c" * 64)
        with self.assertRaises(TransferError):
            gate.read_pair()
        self.assertTrue(gate.is_held)

    def test_native_issuer_rotation_latches_hold(self):
        gate = self.open()
        self.native.issuer = PolicyPin(3, "c" * 64)
        with self.assertRaises(TransferError):
            gate.read_pair()

    def test_native_outage_sticks_hold(self):
        gate = self.open()
        self.native.outage = True
        with self.assertRaises(TransferError):
            gate.read_pair()
        self.native.outage = False
        with self.assertRaises(TransferError):
            gate.read_pair()

    def test_wrong_device_binding_denied(self):
        self.native.identity = replace(self.identity, device_binding=b"x" * 32)
        with self.assertRaises(TransferError):
            self.open()

    def test_wrong_generation_denied(self):
        self.native.identity = replace(self.identity, generation=2)
        with self.assertRaises(TransferError):
            self.open()

    def test_cross_platform_identity_denied(self):
        self.native.identity = replace(
            self.identity, platform=NativePlatform.ANDROID_KEYMINT,
        )
        with self.assertRaises(TransferError):
            self.open()

    def test_namespace_substitution_denied(self):
        self.native.identity = replace(self.identity, namespace=b"x" * 32)
        with self.assertRaises(TransferError):
            self.open()

    def test_wrong_attestation_signer_denied(self):
        self.public = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        with self.assertRaises(TransferError):
            self.open()

    def test_replayed_challenge_denied(self):
        self.native.stale = b"r" * 32
        with self.assertRaises(TransferError):
            self.open()

    def test_invalid_signature_denied(self):
        self.native.corrupt = True
        with self.assertRaises(TransferError):
            self.open()

    def test_invalid_service_rejected(self):
        with self.assertRaises(TransferError):
            AttestedNativePolicyPins(object(), self.identity, self.public)

    def test_invalid_signer_key_rejected(self):
        with self.assertRaises(TransferError):
            AttestedNativePolicyPins(self.native, self.identity, b"short")

    def test_witness_cannot_reset_held_instance(self):
        gate = self.open()
        self.native.policy = PolicyPin(2, "c" * 64)
        with self.assertRaises(TransferError):
            gate.read_pair()
        self.native.policy = PIN1
        with self.assertRaises(TransferError):
            gate.read_pair()

    def test_signature_binds_both_policy_pins(self):
        first = custody_message(self.identity, PIN1, PIN2, b"n" * 32)
        other = custody_message(self.identity, PIN2, PIN1, b"n" * 32)
        self.assertNotEqual(first, other)

    def test_signature_binds_fresh_challenge(self):
        self.assertNotEqual(
            custody_message(self.identity, PIN1, PIN2, b"n" * 32),
            custody_message(self.identity, PIN1, PIN2, b"m" * 32),
        )

    def test_signed_fake_not_hardware_proof(self):
        # A software-only key signs valid-looking claims. This is specifically
        # NOT proof the platform has a hardware-protected monotonic counter.
        self.assertEqual(self.open().issuer_pin(), PIN2)
        self.assertFalse(hasattr(self.native, "trusted_monotonic_hardware"))

    def test_invalid_custody_input_denied(self):
        with self.assertRaises(TransferError):
            custody_message(self.identity, PIN1, PIN2, b"x")

if __name__ == "__main__":
    unittest.main()
