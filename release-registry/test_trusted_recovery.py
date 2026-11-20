"""Offline recovery acceptance/denial tests using a synthetic trust fixture."""
import json
from pathlib import Path
import tempfile
import unittest

from offline_journal import OfflineJournal
from offline_stage import GENESIS, make_candidate
from trusted_recovery import (SCHEMA, RecoveryError, checkpoint_statement,
                              prepare_backup, verify_backup, verify_recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "journal.sqlite"
        self.journal = OfflineJournal(self.path)
        self.events, self.head, _ = self.journal.append(
            make_candidate("rio", "ev1", 1, GENESIS, b"synthetic"),
            expected_head=GENESIS)
        self.scope = "candidate-test"
        self.checkpoint = {"schema": SCHEMA, "scope": self.scope,
                           "sequence": 1, "head": self.head,
                           "receipt": "synthetic-fixture-not-a-signature"}

    @staticmethod
    def fixture_verifier(statement, receipt):
        # NEVER wire this fixture to production.
        return statement.startswith(b"PALACO-TRUSTED-RECOVERY-v2:") and (
            receipt == "synthetic-fixture-not-a-signature")

    def recover(self, **kwargs):
        args = {"scope": self.scope, "verify": self.fixture_verifier}
        args.update(kwargs)
        return verify_recovery(self.journal, self.checkpoint, **args)

    def test_recovery(self):
        self.assertEqual(self.recover(), (self.events, self.head))

    def test_restart(self):
        self.assertEqual(
            verify_recovery(OfflineJournal(self.path), self.checkpoint,
                            scope=self.scope, verify=self.fixture_verifier),
            (self.events, self.head))

    def test_missing_verifier_fails(self):
        with self.assertRaisesRegex(RecoveryError, "TRUST_VERIFIER_REQUIRED"):
            self.recover(verify=None)

    def test_false_verifier_fails(self):
        with self.assertRaisesRegex(RecoveryError, "TRUST_VERIFICATION_FAILED"):
            self.recover(verify=lambda *_: False)

    def test_truthy_non_boolean_fails(self):
        with self.assertRaises(RecoveryError):
            self.recover(verify=lambda *_: 1)

    def test_verifier_exception_fails(self):
        def bad(*_):
            raise RuntimeError("offline")
        with self.assertRaises(RecoveryError):
            self.recover(verify=bad)

    def test_wrong_scope_fails(self):
        with self.assertRaisesRegex(RecoveryError, "SCOPE_MISMATCH"):
            self.recover(scope="another")

    def test_wrong_head_fails(self):
        altered = dict(self.checkpoint, head=GENESIS)
        with self.assertRaises(RecoveryError):
            verify_recovery(self.journal, altered, scope=self.scope,
                            verify=self.fixture_verifier)

    def test_wrong_sequence_fails(self):
        altered = dict(self.checkpoint, sequence=2)
        with self.assertRaisesRegex(RecoveryError, "RECOVERY_STATE_MISMATCH"):
            verify_recovery(self.journal, altered, scope=self.scope,
                            verify=self.fixture_verifier)

    def test_no_receipt_fails(self):
        altered = dict(self.checkpoint, receipt="")
        with self.assertRaisesRegex(RecoveryError, "INVALID_RECEIPT"):
            verify_recovery(self.journal, altered, scope=self.scope,
                            verify=self.fixture_verifier)

    def test_unknown_checkpoint_field_fails(self):
        altered = dict(self.checkpoint, authorized=True)
        with self.assertRaises(RecoveryError):
            verify_recovery(self.journal, altered, scope=self.scope,
                            verify=self.fixture_verifier)

    def test_backup_roundtrip(self):
        backup = prepare_backup(self.journal, self.checkpoint,
                                scope=self.scope, verify=self.fixture_verifier)
        self.assertEqual(verify_backup(backup, self.checkpoint, scope=self.scope,
                                       verify=self.fixture_verifier),
                         (self.events, self.head))

    def test_backup_tampered_payload_fails(self):
        backup = prepare_backup(self.journal, self.checkpoint,
                                scope=self.scope, verify=self.fixture_verifier)
        data = json.loads(backup)
        data["events"][0]["payload_sha256"] = "0" * 64
        corrupted = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(RecoveryError):
            verify_backup(corrupted, self.checkpoint, scope=self.scope,
                          verify=self.fixture_verifier)

    def test_backup_not_canonical_fails(self):
        backup = prepare_backup(self.journal, self.checkpoint,
                                scope=self.scope, verify=self.fixture_verifier)
        with self.assertRaisesRegex(RecoveryError, "NONCANONICAL_BACKUP"):
            verify_backup(backup + b" ", self.checkpoint, scope=self.scope,
                          verify=self.fixture_verifier)

    def test_backup_wrong_scope_fails(self):
        backup = prepare_backup(self.journal, self.checkpoint,
                                scope=self.scope, verify=self.fixture_verifier)
        with self.assertRaises(RecoveryError):
            verify_backup(backup, self.checkpoint, scope="another",
                          verify=self.fixture_verifier)

    def test_backup_rejects_nonbytes(self):
        with self.assertRaises(RecoveryError):
            verify_backup("not bytes", self.checkpoint, scope=self.scope,
                          verify=self.fixture_verifier)

    def test_bad_genesis_statement(self):
        with self.assertRaisesRegex(RecoveryError, "INVALID_GENESIS"):
            checkpoint_statement(scope=self.scope, sequence=0, head=self.head)


if __name__ == "__main__":
    unittest.main()
