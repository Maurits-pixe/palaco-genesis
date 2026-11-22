"""Atomic fencing contract regressions using one locked in-memory fake.

The lock simulates an atomic service only; NOT multi-process secure hardware.
"""
from dataclasses import replace
import threading
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedChallengeAnchor, FencedSnapshot
from protocol import TransferError

NS = b"f" * 32
OTHER = b"o" * 32
ROOT1 = "a" * 64
ROOT2 = "b" * 64


class FakeAtomicService:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = FencedSnapshot(NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT))
        self.offline = False
        self.fail_write = False
        self.uncertain = False
        self.tamper_result = False

    def read(self):
        with self.lock:
            if self.offline:
                raise OSError("fencing backend unavailable")
            return self.state

    def compare_and_advance(self, expected, replacement):
        with self.lock:
            if self.offline or self.fail_write or expected != self.state or self.state.incident_held:
                raise OSError("atomic CAS denied")
            self.state = replace(self.state, checkpoint=replacement)
            if self.uncertain:
                raise OSError("write ack lost")
            return replace(self.state, checkpoint=NativeCheckpoint(NS, 0, EMPTY_ROOT)) if self.tamper_result else self.state

    def revoke(self):
        with self.lock:
            self.state = replace(self.state, epoch=self.state.epoch + 1, incident_held=True)


class FencingGateTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeAtomicService()
        self.anchor = FencedChallengeAnchor(self.service, NS)

    def test_initial_checkpoint(self):
        self.assertEqual(self.anchor.read(), (0, EMPTY_ROOT))

    def test_cas_issue_transition(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.assertEqual(self.anchor.read(), (1, ROOT1))

    def test_cas_consumed_transition(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.anchor.advance((1, ROOT1), (1, ROOT2))
        self.assertEqual(self.anchor.read(), (1, ROOT2))

    def test_native_revocation_denies_read(self):
        self.service.revoke()
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_native_revocation_denies_write(self):
        self.service.revoke()
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))

    def test_later_matching_state_cannot_reset_local_hold(self):
        self.service.revoke()
        with self.assertRaises(TransferError):
            self.anchor.read()
        self.service.state = FencedSnapshot(NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT))
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_epoch_rotation_without_incident_denied(self):
        self.service.state = replace(self.service.state, epoch=2)
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_namespace_swap_denied(self):
        self.service.state = FencedSnapshot(OTHER, 1, False, NativeCheckpoint(OTHER, 0, EMPTY_ROOT))
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_service_unavailable_denied(self):
        self.service.offline = True
        with self.assertRaises(TransferError):
            self.anchor.read()

    def test_invalid_epoch_boolean_denied(self):
        with self.assertRaises(TransferError):
            FencedSnapshot(NS, True, False, NativeCheckpoint(NS, 0, EMPTY_ROOT))

    def test_invalid_incident_boolean_denied(self):
        with self.assertRaises(TransferError):
            FencedSnapshot(NS, 1, 0, NativeCheckpoint(NS, 0, EMPTY_ROOT))

    def test_invalid_checkpoint_denied(self):
        with self.assertRaises(TransferError):
            FencedSnapshot(NS, 1, False, "not checkpoint")

    def test_missing_native_service_denied(self):
        with self.assertRaises(TransferError):
            FencedChallengeAnchor(object(), NS)

    def test_invalid_count_jump_denied(self):
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (2, ROOT1))
        self.assertTrue(self.anchor.is_held)

    def test_duplicate_state_denied(self):
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (0, EMPTY_ROOT))

    def test_stale_cas_denied(self):
        self.service.state = replace(self.service.state, checkpoint=NativeCheckpoint(NS, 1, ROOT1))
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))

    def test_uncertain_write_denied_and_held(self):
        self.service.uncertain = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.assertTrue(self.anchor.is_held)

    def test_bad_return_from_native_denied(self):
        self.service.tamper_result = True
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))

    def test_competing_writers_only_one_success(self):
        from concurrent.futures import ThreadPoolExecutor
        left = self.anchor
        right = FencedChallengeAnchor(self.service, NS)
        def attempt(anchor):
            try:
                anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
                return True
            except TransferError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, (left, right)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 1)

    def test_revoke_between_read_and_cas_denied(self):
        original = self.service.compare_and_advance
        def raced(expected, replacement):
            self.service.revoke()
            return original(expected, replacement)
        self.service.compare_and_advance = raced
        with self.assertRaises(TransferError):
            self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))

    def test_reopen_held_native_denied(self):
        self.service.revoke()
        with self.assertRaises(TransferError):
            FencedChallengeAnchor(self.service, NS)

    def test_unprotected_fake_rollback_still_possible(self):
        self.anchor.advance((0, EMPTY_ROOT), (1, ROOT1))
        self.service.state = FencedSnapshot(NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT))
        # A brand new instance sees a forged old state; genuine monotonic
        # hardware or independently protected witness is still required.
        fresh = FencedChallengeAnchor(self.service, NS)
        self.assertEqual(fresh.read(), (0, EMPTY_ROOT))


if __name__ == "__main__":
    unittest.main()
