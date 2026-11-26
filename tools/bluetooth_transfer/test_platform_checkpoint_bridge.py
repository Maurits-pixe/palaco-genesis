"""Native platform bridge contract tests, using only a synthetic service.

These tests do NOT attest TPM/StrongBox hardware or real anti-rollback.
"""
from dataclasses import replace
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from platform_checkpoint_bridge import (
    NativePlatform, NativeStorageIdentity, PlatformCheckpointBackend,
    bind_windows_tpm, bind_android_keymint,
)
from protocol import TransferError


SCOPE = b"s" * 32
DEVICE = b"d" * 32
ROOT = "b" * 64


class FakeNativeService:
    def __init__(self, identity):
        self.current_identity = identity
        self.checkpoint = NativeCheckpoint(identity.namespace, 0, EMPTY_ROOT)
        self.fail_identity = False
        self.fail_read = False
        self.fail_write = False
        self.change_identity_during_read = False
        self.change_identity_during_write = False
        self.last_write = None

    def identity(self):
        if self.fail_identity:
            raise OSError("native bridge failure")
        return self.current_identity

    def read(self):
        if self.fail_read:
            raise OSError("native read failure")
        if self.change_identity_during_read:
            self.current_identity = replace(
                self.current_identity, generation=self.current_identity.generation + 1,
            )
        return self.checkpoint

    def advance(self, namespace, previous, current):
        self.last_write = (namespace, previous, current)
        if self.fail_write or previous != self.checkpoint:
            raise OSError("CAS error")
        self.checkpoint = current
        if self.change_identity_during_write:
            self.current_identity = replace(
                self.current_identity, device_binding=b"x" * 32,
            )


class PlatformBridgeTests(unittest.TestCase):
    def setUp(self):
        self.win = NativeStorageIdentity(
            NativePlatform.WINDOWS_TPM, SCOPE, DEVICE, 1,
        )
        self.android = NativeStorageIdentity(
            NativePlatform.ANDROID_KEYMINT, SCOPE, DEVICE, 1,
        )
        self.service = FakeNativeService(self.win)

    def test_windows_adapter_reads(self):
        self.assertEqual(bind_windows_tpm(self.service, self.win).read(), (0, EMPTY_ROOT))

    def test_android_adapter_reads(self):
        service = FakeNativeService(self.android)
        self.assertEqual(bind_android_keymint(service, self.android).read(), (0, EMPTY_ROOT))

    def test_windows_real_transition_contract(self):
        anchor = bind_windows_tpm(self.service, self.win)
        anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.assertEqual(anchor.read(), (1, ROOT))

    def test_android_consumption_same_count(self):
        service = FakeNativeService(self.android)
        anchor = bind_android_keymint(service, self.android)
        anchor.advance((0, EMPTY_ROOT), (0, ROOT))
        self.assertEqual(anchor.read(), (0, ROOT))

    def test_windows_identity_rejects_android_service(self):
        self.service.current_identity = self.android
        with self.assertRaises(TransferError):
            bind_windows_tpm(self.service, self.win)

    def test_android_api_rejects_windows_identity(self):
        with self.assertRaises(TransferError):
            bind_android_keymint(self.service, self.win)

    def test_windows_api_rejects_android_identity(self):
        with self.assertRaises(TransferError):
            bind_windows_tpm(self.service, self.android)

    def test_platform_swap_after_open_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.current_identity = self.android
        with self.assertRaises(TransferError):
            anchor.read()

    def test_device_swap_after_open_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.current_identity = replace(self.win, device_binding=b"x" * 32)
        with self.assertRaises(TransferError):
            anchor.read()

    def test_generation_change_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.current_identity = replace(self.win, generation=2)
        with self.assertRaises(TransferError):
            anchor.read()

    def test_namespace_change_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.current_identity = replace(self.win, namespace=b"x" * 32)
        with self.assertRaises(TransferError):
            anchor.read()

    def test_identity_exception_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.fail_identity = True
        with self.assertRaises(TransferError):
            anchor.read()

    def test_read_exception_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.fail_read = True
        with self.assertRaises(TransferError):
            anchor.read()

    def test_write_exception_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.fail_write = True
        with self.assertRaises(TransferError):
            anchor.advance((0, EMPTY_ROOT), (1, ROOT))

    def test_identity_changes_during_read_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.change_identity_during_read = True
        with self.assertRaises(TransferError):
            anchor.read()

    def test_identity_changes_during_write_denied(self):
        anchor = bind_windows_tpm(self.service, self.win)
        self.service.change_identity_during_write = True
        with self.assertRaises(TransferError):
            anchor.advance((0, EMPTY_ROOT), (1, ROOT))

    def test_missing_service_denied(self):
        with self.assertRaises(TransferError):
            bind_windows_tpm(object(), self.win)

    def test_invalid_device_binding_length_denied(self):
        with self.assertRaises(TransferError):
            NativeStorageIdentity(NativePlatform.WINDOWS_TPM, SCOPE, b"bad", 1)

    def test_boolean_generation_denied(self):
        with self.assertRaises(TransferError):
            NativeStorageIdentity(NativePlatform.ANDROID_KEYMINT, SCOPE, DEVICE, True)

    def test_fake_backend_rollback_remains_possible(self):
        anchor = bind_windows_tpm(self.service, self.win)
        anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.service.checkpoint = NativeCheckpoint(SCOPE, 0, EMPTY_ROOT)
        self.assertEqual(anchor.read(), (0, EMPTY_ROOT))


if __name__ == "__main__":
    unittest.main()
