"""v10 persistent policy-ledger regression tests with synthetic registry data."""
import base64
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest

from durable_policy_journal_v10 import DurablePolicyJournal, PolicyJournalError
from policy_ledger_v9 import GENESIS, LedgerError


class DurableJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "policy.sqlite"
        self.journal = DurablePolicyJournal(self.file)
        self.before = {
            "schema": "palaco-key-registry/v8",
            "version": 1,
            "keys": [{
                "key_id": "fixture-a",
                "public_key_b64": base64.b64encode(bytes(range(32))).decode(),
                "status": "active", "scopes": ["candidate"]
            }]
        }
        self.after = copy.deepcopy(self.before)
        self.after["version"] = 2
        self.after["keys"][0]["status"] = "revoked"

    def append_first(self):
        return self.journal.append(
            self.before, self.after, expected_head=GENESIS)

    def test_empty_read(self):
        events, head, snapshot = self.journal.read(expected_head=GENESIS)
        self.assertEqual((events, head, snapshot), ((), GENESIS, None))

    def test_restart_replays(self):
        event, head = self.append_first()
        events, reread_head, snapshot = DurablePolicyJournal(
            self.file).read(expected_head=head)
        self.assertEqual(events, (event,))
        self.assertEqual(reread_head, head)
        self.assertEqual(snapshot, self.after)

    def test_independent_writer_stale_rejected(self):
        _, head = self.append_first()
        with self.assertRaisesRegex(PolicyJournalError, "STALE_CHECKPOINT"):
            DurablePolicyJournal(self.file).append(
                self.before, self.after, expected_head=GENESIS)
        self.assertEqual(self.journal.read(expected_head=head)[1], head)

    def test_rejected_change_rolls_back(self):
        _, head = self.append_first()
        reverted = copy.deepcopy(self.after)
        reverted["version"] = 3
        reverted["keys"][0]["status"] = "active"
        with self.assertRaisesRegex(LedgerError, "REVOCATION_TERMINAL"):
            self.journal.append(self.after, reverted, expected_head=head)
        self.assertEqual(len(self.journal.read(expected_head=head)[0]), 1)

    def test_second_append_recovery(self):
        _, head = self.append_first()
        next_snapshot = copy.deepcopy(self.after)
        next_snapshot["version"] = 3
        next_snapshot["keys"].append({
            "key_id": "fixture-b",
            "public_key_b64": base64.b64encode(b"b" * 32).decode(),
            "status": "revoked", "scopes": ["candidate"]
        })
        event, new_head = DurablePolicyJournal(self.file).append(
            self.after, next_snapshot, expected_head=head)
        history, head_after_restart, snapshot = DurablePolicyJournal(
            self.file).read(expected_head=new_head)
        self.assertEqual(event["sequence"], 2)
        self.assertEqual(len(history), 2)
        self.assertEqual(head_after_restart, new_head)
        self.assertEqual(snapshot, next_snapshot)

    def test_update_trigger_denies(self):
        self.append_first()
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE policy_events SET body=? WHERE sequence=1", (b"x",))

    def test_delete_trigger_denies(self):
        self.append_first()
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM policy_events")

    def test_corruption_detected(self):
        self.append_first()
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER policy_events_no_update")
            db.execute("UPDATE policy_events SET body=? WHERE sequence=1",
                       (b'{"schema":"forged"}',))
        with self.assertRaises(PolicyJournalError):
            DurablePolicyJournal(self.file).read(expected_head=GENESIS)

    def test_sequence_corruption_detected(self):
        self.append_first()
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER policy_events_no_update")
            db.execute("UPDATE policy_events SET sequence=9 WHERE sequence=1")
        with self.assertRaises(PolicyJournalError):
            self.journal.read(expected_head=GENESIS)

    def test_wrong_head_denied(self):
        self.append_first()
        with self.assertRaisesRegex(PolicyJournalError, "STALE_CHECKPOINT"):
            self.journal.read(expected_head=GENESIS)

    def test_missing_trust_denied(self):
        self.append_first()
        with self.assertRaisesRegex(LedgerError, "EXTERNAL_TRUST_REQUIRED"):
            self.journal.inspect_trusted(
                get_trusted_anchor=None, verify_policy=None)

    def test_external_anchor_mismatch_denied(self):
        self.append_first()
        with self.assertRaisesRegex(LedgerError, "ANCHOR_MISMATCH"):
            self.journal.inspect_trusted(
                get_trusted_anchor=lambda: (0, GENESIS),
                verify_policy=lambda *_: True)

    def test_unknown_policy_denied(self):
        _, head = self.append_first()
        with self.assertRaisesRegex(LedgerError, "POLICY_UNVERIFIED"):
            self.journal.inspect_trusted(
                get_trusted_anchor=lambda: (1, head),
                verify_policy=lambda *_: False)

    def test_trusted_fixture_does_not_authorize(self):
        _, head = self.append_first()
        report = self.journal.inspect_trusted(
            get_trusted_anchor=lambda: (1, head),
            verify_policy=lambda *_: True)
        self.assertEqual(report["release"], "HOLD")
        self.assertEqual(report["authorization"], "DENY")
        self.assertIs(report["production_release_enabled"], False)

    def test_empty_ledger_not_trusted(self):
        with self.assertRaisesRegex(LedgerError, "EMPTY_LEDGER_NOT_TRUSTED"):
            self.journal.inspect_trusted(
                get_trusted_anchor=lambda: (0, GENESIS),
                verify_policy=lambda *_: True)

    def test_caller_input_is_frozen(self):
        event, head = self.append_first()
        self.after["keys"][0]["status"] = "active"
        events, _, snapshot = self.journal.read(expected_head=head)
        self.assertEqual(events[0], event)
        self.assertEqual(snapshot["keys"][0]["status"], "revoked")


if __name__ == "__main__":
    unittest.main()
