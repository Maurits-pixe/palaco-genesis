"""v11 secure-policy recovery tests. Synthetic callbacks are not trust."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

from durable_policy_journal_v10 import DurablePolicyJournal
from policy_ledger_v9 import GENESIS
from secure_policy_recovery_v11 import (
    RestoreError, make_backup, inspect_backup, restore_new_journal,
    approval_bytes,
)


class SecurePolicyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()
        self.original = DurablePolicyJournal(self.folder / "source.sqlite")
        before = {"schema": "palaco-key-registry/v8", "version": 1,
                  "keys": [{"key_id": "fixture",
                            "public_key_b64": base64.b64encode(bytes(range(32))).decode(),
                            "status": "active", "scopes": ["candidate"]}]}
        after = copy.deepcopy(before)
        after["version"] = 2
        after["keys"][0]["status"] = "revoked"
        _, self.head = self.original.append(before, after, expected_head=GENESIS)
        self.events, _, _ = self.original.read(expected_head=self.head)
        self.backup = make_backup(self.events)
        self.destination = self.folder / "restore.sqlite"

    def anchor(self):
        return (len(self.events), self.head)

    def accept(self, **changes):
        params = {"get_trusted_anchor": self.anchor,
                  "verify_policy": lambda *_: True,
                  "approve": lambda *_: True}
        params.update(changes)
        return restore_new_journal(self.backup, self.destination, **params)

    def test_new_file_restore(self):
        result = self.accept()
        self.assertEqual(result["head"], self.head)
        self.assertEqual(DurablePolicyJournal(self.destination).read(
            expected_head=self.head)[0], self.events)

    def test_source_unchanged(self):
        self.accept()
        self.assertEqual(self.original.read(expected_head=self.head)[0], self.events)

    def test_denies_release(self):
        report = self.accept()
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_existing_destination_preserved(self):
        self.destination.write_bytes(b"do-not-overwrite")
        with self.assertRaises(RestoreError):
            self.accept()
        self.assertEqual(self.destination.read_bytes(), b"do-not-overwrite")

    def test_repeated_restore_denied(self):
        self.accept()
        with self.assertRaises(RestoreError):
            self.accept()

    def test_no_approval(self):
        with self.assertRaisesRegex(RestoreError, "APPROVAL_REQUIRED"):
            self.accept(approve=None)
        self.assertFalse(self.destination.exists())

    def test_false_approval(self):
        with self.assertRaisesRegex(RestoreError, "APPROVAL_DENIED"):
            self.accept(approve=lambda _: False)

    def test_truthy_nonboolean_approval(self):
        with self.assertRaisesRegex(RestoreError, "APPROVAL_DENIED"):
            self.accept(approve=lambda _: 1)

    def test_approval_exception(self):
        def fail(_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(RestoreError, "APPROVAL_UNAVAILABLE"):
            self.accept(approve=fail)

    def test_missing_anchor(self):
        with self.assertRaises(RestoreError):
            self.accept(get_trusted_anchor=None)

    def test_older_anchor(self):
        with self.assertRaises(RestoreError):
            self.accept(get_trusted_anchor=lambda: (0, GENESIS))

    def test_false_policy(self):
        with self.assertRaises(RestoreError):
            self.accept(verify_policy=lambda *_: False)

    def test_truthy_nonboolean_policy(self):
        with self.assertRaises(RestoreError):
            self.accept(verify_policy=lambda *_: 1)

    def test_tampered_backup(self):
        corrupted = json.loads(self.backup)
        corrupted["events"][0]["after"]["keys"][0]["status"] = "active"
        data = json.dumps(corrupted, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(RestoreError):
            inspect_backup(data, get_trusted_anchor=self.anchor,
                           verify_policy=lambda *_: True)

    def test_noncanonical_backup(self):
        with self.assertRaisesRegex(RestoreError, "NONCANONICAL_BACKUP"):
            inspect_backup(self.backup + b" ", get_trusted_anchor=self.anchor,
                           verify_policy=lambda *_: True)

    def test_relative_destination(self):
        with self.assertRaises(RestoreError):
            restore_new_journal(self.backup, "relative.sqlite",
                get_trusted_anchor=self.anchor, verify_policy=lambda *_: True,
                approve=lambda *_: True)

    def test_missing_parent(self):
        with self.assertRaises(RestoreError):
            restore_new_journal(self.backup, self.folder / "missing" / "new.sqlite",
                get_trusted_anchor=self.anchor, verify_policy=lambda *_: True,
                approve=lambda *_: True)

    def test_approval_binding(self):
        first = approval_bytes(data=self.backup, destination_name="one.sqlite",
                               sequence=1, head=self.head)
        second = approval_bytes(data=self.backup, destination_name="two.sqlite",
                                sequence=1, head=self.head)
        self.assertNotEqual(first, second)

    def test_no_approval_when_anchor_invalid(self):
        calls = []
        def approve(statement):
            calls.append(statement)
            return True
        with self.assertRaises(RestoreError):
            self.accept(get_trusted_anchor=lambda: (0, GENESIS), approve=approve)
        self.assertEqual(calls, [])

    def test_empty_ledger_denied(self):
        with self.assertRaises(RestoreError):
            inspect_backup(make_backup(()), get_trusted_anchor=lambda: (0, GENESIS),
                           verify_policy=lambda *_: True)


if __name__ == "__main__":
    unittest.main()
