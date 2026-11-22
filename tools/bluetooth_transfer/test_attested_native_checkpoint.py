"""Native signed-snapshot verification tests; generated keys are NOT hardware."""
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anchored_challenges import EMPTY_ROOT
from attested_native_checkpoint import (
    AttestedCheckpointBackend, SignedCheckpointSnapshot,
    bind_attested_native_checkpoint, signed_snapshot_message,
)
from native_checkpoint_scope import NativeCheckpoint
from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError

SCOPE = b"s" * 32
DEVICE = b"d" * 32
ROOT2 = "b" * 64


def public_bytes(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


class FakeAttestingService:
    """Software-only signing; does not prove TPM/KeyMint or anti-rollback."""

    def __init__(self, signer, identity):
        self.signer = signer
        self.identity = identity
        self.checkpoint = NativeCheckpoint(identity.namespace, 0, EMPTY_ROOT)
        self.override_challenge = None
        self.override_signature = None
        self.override_identity = None
        self.override_checkpoint = None
        self.offline = False
        self.reject_write = False
        self.wrong_write = False
        self.last_challenges = []

    def attest(self, challenge):
        if self.offline:
            raise OSError("unavailable")
        self.last_challenges.append(challenge)
        identity = self.override_identity or self.identity
        checkpoint = self.override_checkpoint or self.checkpoint
        signed_for = challenge
        signature = self.signer.sign(
            signed_snapshot_message(identity, checkpoint, signed_for),
        )
        return SignedCheckpointSnapshot(
            identity, checkpoint,
            challenge if self.override_challenge is None else self.override_challenge,
            signature if self.override_signature is None else self.override_signature,
        )

    def advance(self, namespace, previous, current):
        if self.reject_write or namespace != self.identity.namespace or previous != self.checkpoint:
            raise OSError("CAS failed")
        self.checkpoint = (
            replace(current, root="c" * 64) if self.wrong_write else current
        )


class AttestedNativeTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        self.identity = NativeStorageIdentity(
            NativePlatform.WINDOWS_TPM, SCOPE, DEVICE, 3,
        )
        self.service = FakeAttestingService(self.signer, self.identity)

    def bind(self, signer=None):
        return bind_attested_native_checkpoint(
            self.service, self.identity,
            public_bytes(self.signer if signer is None else signer),
        )

    def test_genuine_ed25519_attestation_reads(self):
        self.assertEqual(self.bind().read(), (0, EMPTY_ROOT))

    def test_fresh_challenge_each_read(self):
        anchor = self.bind()
        anchor.read()
        anchor.read()
        self.assertGreaterEqual(len(self.service.last_challenges), 4)
        self.assertEqual(len(set(self.service.last_challenges)), len(self.service.last_challenges))

    def test_write_verified_by_new_signed_snapshot(self):
        anchor = self.bind()
        anchor.advance((0, EMPTY_ROOT), (1, ROOT2))
        self.assertEqual(anchor.read(), (1, ROOT2))

    def test_same_count_content_update(self):
        anchor = self.bind()
        anchor.advance((0, EMPTY_ROOT), (0, ROOT2))
        self.assertEqual(anchor.read(), (0, ROOT2))

    def test_wrong_signer_denied(self):
        with self.assertRaises(TransferError):
            self.bind(signer=self.other)

    def test_forged_signature_denied(self):
        self.service.override_signature = b"x" * 64
        with self.assertRaises(TransferError):
            self.bind()

    def test_wrong_challenge_denied(self):
        self.service.override_challenge = b"x" * 32
        with self.assertRaises(TransferError):
            self.bind()

    def test_wrong_platform_denied(self):
        self.service.override_identity = replace(
            self.identity, platform=NativePlatform.ANDROID_KEYMINT,
        )
        with self.assertRaises(TransferError):
            self.bind()

    def test_other_device_denied(self):
        self.service.override_identity = replace(
            self.identity, device_binding=b"x" * 32,
        )
        with self.assertRaises(TransferError):
            self.bind()

    def test_generation_mismatch_denied(self):
        self.service.override_identity = replace(self.identity, generation=4)
        with self.assertRaises(TransferError):
            self.bind()

    def test_namespace_mismatch_denied(self):
        self.service.override_identity = replace(self.identity, namespace=b"x" * 32)
        self.service.override_checkpoint = NativeCheckpoint(b"x" * 32, 0, EMPTY_ROOT)
        with self.assertRaises(TransferError):
            self.bind()

    def test_attested_count_modified_denied(self):
        self.service.override_checkpoint = NativeCheckpoint(SCOPE, 1, ROOT2)
        self.service.override_signature = self.signer.sign(
            signed_snapshot_message(self.identity, self.service.checkpoint, b"x" * 32),
        )
        with self.assertRaises(TransferError):
            self.bind()

    def test_malformed_checkpoint_denied(self):
        with self.assertRaises(TransferError):
            signed_snapshot_message(self.identity, "wrong", b"x" * 32)

    def test_missing_service_denied(self):
        with self.assertRaises(TransferError):
            bind_attested_native_checkpoint(object(), self.identity, public_bytes(self.signer))

    def test_missing_trusted_public_key_denied(self):
        with self.assertRaises(TransferError):
            bind_attested_native_checkpoint(self.service, self.identity, b"")

    def test_unavailable_attestation_denied(self):
        anchor = self.bind()
        self.service.offline = True
        with self.assertRaises(TransferError):
            anchor.read()

    def test_rejected_write_denied(self):
        anchor = self.bind()
        self.service.reject_write = True
        with self.assertRaises(TransferError):
            anchor.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_wrong_postwrite_checkpoint_denied(self):
        anchor = self.bind()
        self.service.wrong_write = True
        with self.assertRaises(TransferError):
            anchor.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_old_checkpoint_cas_denied(self):
        anchor = self.bind()
        anchor.advance((0, EMPTY_ROOT), (1, ROOT2))
        with self.assertRaises(TransferError):
            anchor.advance((0, EMPTY_ROOT), (1, "c" * 64))

    def test_software_signer_can_sign_rolled_back_state(self):
        anchor = self.bind()
        anchor.advance((0, EMPTY_ROOT), (1, ROOT2))
        self.service.checkpoint = NativeCheckpoint(SCOPE, 0, EMPTY_ROOT)
        # Valid signature over rolled-back state: hardware trust still absent.
        self.assertEqual(anchor.read(), (0, EMPTY_ROOT))


if __name__ == "__main__":
    unittest.main()
