"""Acceptance and denial tests for candidate new-file-only restore."""
from pathlib import Path
import tempfile
import unittest

from offline_journal import OfflineJournal
from offline_stage import GENESIS, make_candidate
from trusted_recovery import SCHEMA, RecoveryError, prepare_backup
from secure_restore import approval_statement, restore_to_new_file


class SecureRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()
        self.original = OfflineJournal(self.folder / "original.sqlite")
        self.events, self.head, _ = self.original.append(
            make_candidate("rio", "one", 1, GENESIS, b"synthetic"),
            expected_head=GENESIS)
        self.scope = "sandbox"
        self.checkpoint = {"schema": SCHEMA, "scope": self.scope,
                           "sequence": 1, "head": self.head,
                           "receipt": "fixture"}
        self.backup = prepare_backup(
            self.original, self.checkpoint, scope=self.scope,
            verify=self.fixture_verify)
        self.target = self.folder / "restored.sqlite"

    @staticmethod
    def fixture_verify(statement, receipt):
        # Synthetic fixture ONLY, not a real trust anchor.
        return receipt == "fixture"

    @staticmethod
    def fixture_approve(statement):
        # Synthetic fixture ONLY, not verified human consent.
        return statement.startswith(b"PALACO-SECURE-RESTORE-v3:APPROVAL")

    def restore(self, **kwargs):
        parameters = {
            "scope": self.scope, "verify": self.fixture_verify,
            "approve": self.fixture_approve, "destination": self.target
        }
        parameters.update(kwargs)
        return restore_to_new_file(self.backup, self.checkpoint, **parameters)

    def test_new_file_restores(self):
        target, head, count = self.restore()
        self.assertEqual((target, head, count), (str(self.target), self.head, 1))
        self.assertEqual(OfflineJournal(self.target).read(expected_head=head)[0],
                         self.events)

    def test_original_unchanged(self):
        self.restore()
        self.assertEqual(self.original.read(expected_head=self.head)[0], self.events)

    def test_target_already_exists(self):
        self.target.write_bytes(b"keep")
        with self.assertRaises(RecoveryError):
            self.restore()
        self.assertEqual(self.target.read_bytes(), b"keep")

    def test_repeat_restore_denied(self):
        self.restore()
        with self.assertRaises(RecoveryError):
            self.restore()

    def test_missing_approval(self):
        with self.assertRaisesRegex(RecoveryError, "APPROVAL_REQUIRED"):
            self.restore(approve=None)
        self.assertFalse(self.target.exists())

    def test_false_approval(self):
        with self.assertRaisesRegex(RecoveryError, "APPROVAL_FAILED"):
            self.restore(approve=lambda _: False)

    def test_truthy_approval_rejected(self):
        with self.assertRaises(RecoveryError):
            self.restore(approve=lambda _: 1)

    def test_approval_exception(self):
        def raised(_):
            raise RuntimeError("unavailable")
        with self.assertRaises(RecoveryError):
            self.restore(approve=raised)

    def test_missing_trust_verifier(self):
        with self.assertRaises(RecoveryError):
            self.restore(verify=None)
        self.assertFalse(self.target.exists())

    def test_wrong_checkpoint(self):
        changed = dict(self.checkpoint, head=GENESIS)
        with self.assertRaises(RecoveryError):
            restore_to_new_file(
                self.backup, changed, scope=self.scope,
                verify=self.fixture_verify, approve=self.fixture_approve,
                destination=self.target)

    def test_mutated_backup(self):
        with self.assertRaises(RecoveryError):
            restore_to_new_file(
                self.backup + b"x", self.checkpoint, scope=self.scope,
                verify=self.fixture_verify, approve=self.fixture_approve,
                destination=self.target)

    def test_relative_destination(self):
        with self.assertRaises(RecoveryError):
            self.restore(destination=Path("relative.sqlite"))

    def test_missing_parent(self):
        with self.assertRaises(RecoveryError):
            self.restore(destination=self.folder / "missing" / "new.sqlite")

    def test_hidden_destination(self):
        with self.assertRaises(RecoveryError):
            self.restore(destination=self.folder / ".hidden")

    def test_approval_statement_binds_content(self):
        a = approval_statement(
            scope=self.scope, checkpoint=self.checkpoint,
            backup_bytes=self.backup, destination="a.sqlite")
        b = approval_statement(
            scope=self.scope, checkpoint=self.checkpoint,
            backup_bytes=self.backup, destination="b.sqlite")
        self.assertNotEqual(a, b)
        c = approval_statement(
            scope=self.scope, checkpoint=self.checkpoint,
            backup_bytes=self.backup + b"x", destination="a.sqlite")
        self.assertNotEqual(a, c)

    def test_approval_never_called_on_invalid_backup(self):
        calls = []
        def approve(statement):
            calls.append(statement)
            return True
        with self.assertRaises(RecoveryError):
            self.restore(approve=approve, verify=None)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
