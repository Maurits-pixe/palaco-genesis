"""Durable HOLD contract regressions. Fake stores are NOT secure hardware."""
from dataclasses import replace
import unittest

from anchored_challenges import EMPTY_ROOT
from durable_hold_gate import (
    DurableHoldChallengeAnchor, ProtectedHoldState,
)
from protocol import TransferError

NAMESPACE = b"h" * 32
OTHER = b"z" * 32
ROOT = "c" * 64


class FakeIncidentStore:
    """Shared volatile fake persists only across test object recreations."""

    def __init__(self):
        self.value = ProtectedHoldState(NAMESPACE, False, 0)
        self.offline = False
        self.refuse = False
        self.uncertain = False
        self.wrong_scope = False
        self.calls = 0

    def read(self):
        if self.offline:
            raise OSError("incident backend offline")
        if self.wrong_scope:
            return replace(self.value, namespace=OTHER)
        return self.value

    def latch(self, namespace):
        self.calls += 1
        if self.refuse or namespace != NAMESPACE:
            raise OSError("could not persist incident")
        self.value = ProtectedHoldState(NAMESPACE, True, 1)
        if self.uncertain:
            raise OSError("write acknowledgment lost")
        return self.value


class FakeCheckpoint:
    def __init__(self):
        self.value = (0, EMPTY_ROOT)
        self.fail_read = False
        self.fail_write = False
        self.uncertain = False
        self.reads = 0
        self.writes = 0

    def read(self):
        self.reads += 1
        if self.fail_read:
            raise OSError("native read failed")
        return self.value

    def advance(self, before, after):
        self.writes += 1
        if self.fail_write or self.value != before:
            raise OSError("native CAS failed")
        self.value = after
        if self.uncertain:
            raise OSError("write confirmation missing")


class DurableHoldGateTests(unittest.TestCase):
    def setUp(self):
        self.incidents = FakeIncidentStore()
        self.native = FakeCheckpoint()
        self.anchor = DurableHoldChallengeAnchor(
            self.native, self.incidents, NAMESPACE,
        )

    def new(self):
        return DurableHoldChallengeAnchor(self.native, self.incidents, NAMESPACE)

    def test_initial_healthy_read(self):
        self.assertEqual(self.anchor.read(), (0, EMPTY_ROOT))

    def test_valid_checkpoint_write(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.assertEqual(self.anchor.read(), (1, ROOT))
        self.assertFalse(self.incidents.value.held)

    def test_failed_read_latches_durably_in_fake(self):
        self.native.fail_read = True
        with self.assertRaises(TransferError):
            self.anchor.read()
        self.assertTrue(self.incidents.value.held)

    def test_restart_rejects_latched_incident(self):
        self.native.fail_read = True
        with self.assertRaises(TransferError):
            self.anchor.read()
        self.native.fail_read = False
        with self.assertRaises(TransferError):
            self.new()

    def test_forged_matching_checkpoint_does_not_clear_hold(self):
        self.native.fail_write = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.native.fail_write = False
        self.native.value = (1, ROOT)
        with self.assertRaises(TransferError):
            self.new()

    def test_write_failure_latches(self):
        self.native.fail_write = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.assertTrue(self.incidents.value.held)

    def test_uncertain_write_latches(self):
        self.native.uncertain = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.assertEqual(self.native.value, (1, ROOT))
        self.assertTrue(self.incidents.value.held)

    def test_restored_incident_store_keeps_local_hold(self):
        self.incidents.offline = True
        with self.assertRaises(TransferError):
            self.anchor.read()
        self.incidents.offline = False
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_incident_store_offline_at_construction(self):
        self.incidents.offline = True
        with self.assertRaises(TransferError):
            self.new()

    def test_wrong_store_namespace_denied(self):
        self.incidents.wrong_scope = True
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_wrong_scope_after_reopen_denied(self):
        self.incidents.wrong_scope = True
        with self.assertRaises(TransferError):
            self.new()

    def test_latch_write_failure_causes_local_hold(self):
        self.native.fail_write = True
        self.incidents.refuse = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.assertTrue(self.anchor.is_held)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_latch_acknowledgment_lost_still_holds(self):
        self.native.fail_write = True
        self.incidents.uncertain = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        self.assertTrue(self.incidents.value.held)

    def test_no_unlatch_method(self):
        self.assertFalse(hasattr(self.anchor, "clear"))
        self.assertFalse(hasattr(self.anchor, "unlock"))

    def test_already_held_store_refuses_new_instance(self):
        self.incidents.value = ProtectedHoldState(NAMESPACE, True, 1)
        with self.assertRaises(TransferError):
            self.new()

    def test_invalid_incident_sequence_bool(self):
        with self.assertRaises(TransferError):
            ProtectedHoldState(NAMESPACE, False, True)

    def test_invalid_held_without_sequence(self):
        with self.assertRaises(TransferError):
            ProtectedHoldState(NAMESPACE, True, 0)

    def test_invalid_unheld_with_sequence(self):
        with self.assertRaises(TransferError):
            ProtectedHoldState(NAMESPACE, False, 1)

    def test_missing_store_denied(self):
        with self.assertRaises(TransferError):
            DurableHoldChallengeAnchor(self.native, object(), NAMESPACE)

    def test_fake_rollback_of_incident_still_possible(self):
        self.native.fail_write = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT))
        # Demonstrates what a compromised unprotected fake can do on restart.
        self.incidents.value = ProtectedHoldState(NAMESPACE, False, 0)
        self.native.fail_write = False
        fresh = self.new()
        self.assertFalse(fresh.is_held)


if __name__ == "__main__":
    unittest.main()
