"""Candidate-only offline stage negative controls."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offline_stage import (
    GENESIS, StageError, make_candidate, replay, stage
)


class OfflineStageTests(unittest.TestCase):
    def setUp(self):
        self.first = make_candidate("rio", "e-1", 1, GENESIS, b"test-only")

    def rejects(self, history, event, head):
        with self.assertRaises(StageError):
            stage(history, event, expected_head=head)

    def test_empty_genesis(self):
        self.assertEqual(replay(()), GENESIS)

    def test_stage_and_replay(self):
        history, head, retry = stage((), self.first, expected_head=GENESIS)
        self.assertFalse(retry)
        self.assertEqual(replay(history), head)

    def test_identical_retry(self):
        history, head, _ = stage((), self.first, expected_head=GENESIS)
        again, same_head, retry = stage(history, self.first, expected_head=head)
        self.assertTrue(retry)
        self.assertEqual((again, same_head), (history, head))

    def test_conflicting_retry(self):
        history, head, _ = stage((), self.first, expected_head=GENESIS)
        changed = dict(self.first, payload_sha256="0" * 64)
        self.rejects(history, changed, head)

    def test_stale_checkpoint(self):
        history, head, _ = stage((), self.first, expected_head=GENESIS)
        next_event = make_candidate("mundo", "e-2", 2, head, b"test")
        self.rejects(history, next_event, GENESIS)

    def test_out_of_order(self):
        future = make_candidate("rio", "e-2", 2, GENESIS, b"test")
        self.rejects((), future, GENESIS)

    def test_wrong_previous(self):
        changed = dict(self.first, previous="0" * 64)
        self.rejects((), changed, GENESIS)

    def test_mutated_history(self):
        history, head, _ = stage((), self.first, expected_head=GENESIS)
        corrupt = dict(history[0], payload_sha256="a" * 64)
        with self.assertRaises(StageError):
            replay((corrupt,))

    def test_extra_authority_field(self):
        changed = dict(self.first, authorized=True)
        self.rejects((), changed, GENESIS)

    def test_unknown_module(self):
        changed = dict(self.first, module="stranger")
        self.rejects((), changed, GENESIS)

    def test_duplicate_ids_in_replay(self):
        history, head, _ = stage((), self.first, expected_head=GENESIS)
        second = make_candidate("rio", "e-1", 2, head, b"other")
        with self.assertRaises(StageError):
            replay(history + (second,))

    def test_boolean_sequence(self):
        changed = dict(self.first, sequence=True)
        self.rejects((), changed, GENESIS)

    def test_invalid_event_id(self):
        changed = dict(self.first, event_id="../")
        self.rejects((), changed, GENESIS)

    def test_unknown_payload(self):
        with self.assertRaises(StageError):
            make_candidate("rio", "e-1", 1, GENESIS, "plaintext")

    def test_caller_object_frozen(self):
        event = copy.deepcopy(self.first)
        history, head, _ = stage((), event, expected_head=GENESIS)
        event["module"] = "mundo"
        self.assertEqual(history[0]["module"], "rio")
        self.assertEqual(replay(history), head)

    def test_rejected_history_preserves_input(self):
        history, head, _ = stage((), self.first, expected_head=GENESIS)
        original = copy.deepcopy(history)
        self.rejects(history, make_candidate("mundo", "e-2", 2, "0" * 64, b"x"), head)
        self.assertEqual(history, original)


if __name__ == "__main__":
    unittest.main()
