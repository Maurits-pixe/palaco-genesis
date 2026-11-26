"""Namespace checkpoint contract tests; backend is a non-secure fake."""
from dataclasses import replace
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import (
    NativeCheckpoint, ScopeBoundChallengeAnchor,
)
from protocol import TransferError


SCOPE = b"a" * 32
OTHER = b"b" * 32
ROOT2 = "b" * 64
ROOT3 = "c" * 64


class FakeBackend:
    def __init__(self):
        self.value = NativeCheckpoint(SCOPE, 0, EMPTY_ROOT)
        self.unavailable = False
        self.reject = False
        self.uncertain = False
        self.write_wrong = False
        self.calls = 0

    def read(self):
        if self.unavailable:
            raise OSError("backend unavailable")
        return self.value

    def advance(self, namespace, previous, current):
        self.calls += 1
        if self.reject or namespace != SCOPE or previous != self.value:
            raise OSError("CAS denied")
        self.value = replace(current, root=ROOT3) if self.write_wrong else current
        if self.uncertain:
            raise OSError("ack lost")


class CheckpointScopeTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.wrapper = ScopeBoundChallengeAnchor(self.backend, SCOPE)

    def test_initial_read(self):
        self.assertEqual(self.wrapper.read(), (0, EMPTY_ROOT))

    def test_count_increment(self):
        self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))
        self.assertEqual(self.wrapper.read(), (1, ROOT2))

    def test_same_count_changed_content(self):
        self.wrapper.advance((0, EMPTY_ROOT), (0, ROOT2))
        self.assertEqual(self.wrapper.read(), (0, ROOT2))

    def test_same_state_denied(self):
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (0, EMPTY_ROOT))

    def test_count_jump_denied(self):
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (2, ROOT2))

    def test_count_regression_denied(self):
        self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))
        with self.assertRaises(TransferError):
            self.wrapper.advance((1, ROOT2), (0, ROOT3))

    def test_wrong_scope_at_constructor_denied(self):
        with self.assertRaises(TransferError):
            ScopeBoundChallengeAnchor(self.backend, OTHER)

    def test_scope_switched_after_open_denied(self):
        self.backend.value = NativeCheckpoint(OTHER, 0, EMPTY_ROOT)
        with self.assertRaises(TransferError):
            self.wrapper.read()

    def test_scope_switched_before_write_denied(self):
        self.backend.value = NativeCheckpoint(OTHER, 0, EMPTY_ROOT)
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_backend_unavailable_denied(self):
        self.backend.unavailable = True
        with self.assertRaises(TransferError):
            self.wrapper.read()

    def test_backend_uncertain_write_holds(self):
        self.backend.uncertain = True
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_backend_reject_holds(self):
        self.backend.reject = True
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_wrong_acknowledged_content_holds(self):
        self.backend.write_wrong = True
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_stale_checkpoint_precondition_holds(self):
        self.backend.value = NativeCheckpoint(SCOPE, 0, ROOT3)
        with self.assertRaises(TransferError):
            self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))

    def test_invalid_scope_length_denied(self):
        with self.assertRaises(TransferError):
            ScopeBoundChallengeAnchor(self.backend, b"short")

    def test_invalid_native_checkpoint_denied(self):
        with self.assertRaises(TransferError):
            NativeCheckpoint(SCOPE, True, EMPTY_ROOT)

    def test_missing_backend_denied(self):
        with self.assertRaises(TransferError):
            ScopeBoundChallengeAnchor(object(), SCOPE)

    def test_rollback_of_fake_not_detected_without_hardware(self):
        self.wrapper.advance((0, EMPTY_ROOT), (1, ROOT2))
        self.backend.value = NativeCheckpoint(SCOPE, 0, EMPTY_ROOT)
        # This deliberately shows why a REAL native monotonic backend is needed.
        self.assertEqual(self.wrapper.read(), (0, EMPTY_ROOT))


if __name__ == "__main__":
    unittest.main()
