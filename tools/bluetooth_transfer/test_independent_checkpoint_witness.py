"""Synthetic independent checkpoint witness regressions.

Both stores are fake mutable memory; hardware rollback security is NOT tested.
"""
from dataclasses import replace
import unittest

from anchored_challenges import EMPTY_ROOT
from independent_checkpoint_witness import (
    WitnessCheckpoint, WitnessedChallengeAnchor,
)
from protocol import TransferError

SCOPE = b"w" * 32
OTHER = b"x" * 32
ROOT1 = "b" * 64
ROOT2 = "c" * 64


class FakeNative:
    def __init__(self):
        self.state = (0, EMPTY_ROOT)
        self.offline = False
        self.reject = False
        self.uncertain = False
        self.on_read = None

    def read(self):
        if self.offline:
            raise OSError("native unavailable")
        if self.on_read is not None:
            self.on_read()
        return self.state

    def advance(self, previous, current):
        if self.reject or self.state != previous:
            raise OSError("native CAS error")
        if self.uncertain:
            self.state = current
            raise OSError("lost acknowledgement")
        self.state = current


class FakeWitness:
    def __init__(self):
        self.state = WitnessCheckpoint(SCOPE, 0, 0, EMPTY_ROOT)
        self.offline = False
        self.reject = False
        self.uncertain = False
        self.on_read = None

    def read(self):
        if self.offline:
            raise OSError("witness unavailable")
        if self.on_read is not None:
            self.on_read()
        return self.state

    def advance(self, previous, current):
        if self.reject or self.state != previous:
            raise OSError("witness CAS error")
        if self.uncertain:
            self.state = current
            raise OSError("lost acknowledgement")
        self.state = current


class IndependentWitnessTests(unittest.TestCase):
    def setUp(self):
        self.native = FakeNative()
        self.witness = FakeWitness()
        self.anchor = WitnessedChallengeAnchor(self.native, self.witness, SCOPE)

    def test_initial_state(self):
        self.assertEqual(self.anchor.read(), (0, EMPTY_ROOT))

    def test_issue_transition(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.assertEqual(self.anchor.read(), (1, ROOT1))
        self.assertEqual(self.witness.state.revision, 1)

    def test_consumption_same_count_increments_revision(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.anchor.advance((1, ROOT1), (1, ROOT2))
        self.assertEqual(self.witness.state.revision, 2)
        self.assertEqual(self.anchor.read(), (1, ROOT2))

    def test_replayed_old_native_checkpoint_rejected(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.native.state = (0, EMPTY_ROOT)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_native_same_count_reactivation_rejected(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.anchor.advance((1, ROOT1), (1, ROOT2))
        self.native.state = (1, ROOT1)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_witness_rollback_alone_rejected(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.witness.state = WitnessCheckpoint(SCOPE, 0, 0, EMPTY_ROOT)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_wrong_witness_namespace_denied(self):
        self.witness.state = replace(self.witness.state, namespace=OTHER)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_missing_witness_denied(self):
        self.witness.offline = True
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_missing_native_denied(self):
        self.native.offline = True
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_witness_rejects_write_without_native_change(self):
        self.witness.reject = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.assertEqual(self.native.state, (0, EMPTY_ROOT))

    def test_native_failure_after_witness_write_holds(self):
        self.native.reject = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.assertEqual(self.witness.state.revision, 1)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_uncertain_witness_advance_holds(self):
        self.witness.uncertain = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_uncertain_native_write_holds(self):
        self.native.uncertain = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        # Even if both stores landed correctly, the acknowledgement was lost:
        # the caller receives HOLD, never an automatic approval.
        self.assertEqual(self.anchor.read(), (1, ROOT1))

    def test_wrong_previous_checkpoint_denied(self):
        with self.assertRaises(TransferError):
            self.anchor.advance((1, ROOT1), (2, ROOT2))

    def test_invalid_count_jump_denied(self):
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (2, ROOT1))

    def test_identical_checkpoint_denied(self):
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (0, EMPTY_ROOT))

    def test_invalid_witness_revision_denied(self):
        with self.assertRaises(TransferError):
            WitnessCheckpoint(SCOPE, True, 0, EMPTY_ROOT)

    def test_invalid_witness_scope_denied(self):
        with self.assertRaises(TransferError):
            WitnessCheckpoint(b"short", 0, 0, EMPTY_ROOT)

    def test_missing_witness_interface_denied(self):
        with self.assertRaises(TransferError):
            WitnessedChallengeAnchor(self.native, object(), SCOPE)

    def test_both_fakes_rolled_back_cannot_be_detected(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.native.state = (0, EMPTY_ROOT)
        self.witness.state = WitnessCheckpoint(SCOPE, 0, 0, EMPTY_ROOT)
        self.assertEqual(self.anchor.read(), (0, EMPTY_ROOT))


if __name__ == "__main__":
    unittest.main()
