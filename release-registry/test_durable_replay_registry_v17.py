"""PALACO v17 SQLite replay-registry regression checks.

Synthetic signing keys and synthetic payloads only. Tests are not production
identity, revocation, or trusted durable storage verification.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from durable_replay_registry_v17 import DurableReplayRegistry, ReplayRegistryError


class ReplayRegistryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "claims.sqlite"
        self.reg = DurableReplayRegistry(self.path)
        self.d1 = hashlib.sha256(b"first").hexdigest()
        self.d2 = hashlib.sha256(b"second").hexdigest()

    def claim(self, *, sender="sender", recipient="recipient",
              message="message", digest=None, registry=None):
        return (self.reg if registry is None else registry)(
            sender, recipient, message, self.d1 if digest is None else digest)

    def test_first_claim_returns_true(self):
        self.assertIs(self.claim(), True)

    def test_duplicate_claim_returns_false(self):
        self.assertIs(self.claim(), True)
        self.assertIs(self.claim(), False)

    def test_modified_ciphertext_same_id_denied(self):
        self.claim()
        self.assertIs(self.claim(digest=self.d2), False)
        self.assertEqual(self.reg.inspect("sender", "recipient", "message"), self.d1)

    def test_restart_retains_claim(self):
        self.claim()
        second = DurableReplayRegistry(self.path)
        self.assertIs(self.claim(registry=second), False)

    def test_distinct_message_ids_allowed(self):
        self.assertIs(self.claim(message="first"), True)
        self.assertIs(self.claim(message="second"), True)

    def test_distinct_recipients_allowed(self):
        self.assertIs(self.claim(recipient="one"), True)
        self.assertIs(self.claim(recipient="two"), True)

    def test_distinct_senders_allowed(self):
        self.assertIs(self.claim(sender="one"), True)
        self.assertIs(self.claim(sender="two"), True)

    def test_concurrent_only_one_succeeds(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: self.claim(), range(16)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 15)

    def test_independent_instances_only_one_succeeds(self):
        alternate = DurableReplayRegistry(self.path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda registry: self.claim(registry=registry),
                [self.reg, alternate]))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 1)

    def test_bad_digest_denied(self):
        with self.assertRaisesRegex(ReplayRegistryError, "INVALID_PACKAGE_DIGEST"):
            self.claim(digest="bad")

    def test_boolean_digest_denied(self):
        with self.assertRaises(ReplayRegistryError):
            self.claim(digest=True)

    def test_invalid_message_id_denied(self):
        with self.assertRaisesRegex(ReplayRegistryError, "INVALID_MESSAGE_IDENTITY"):
            self.claim(message="../../path")

    def test_invalid_sender_denied(self):
        with self.assertRaises(ReplayRegistryError):
            self.claim(sender="")

    def test_invalid_recipient_denied(self):
        with self.assertRaises(ReplayRegistryError):
            self.claim(recipient="bad value")

    def test_no_claim_on_validation_failure(self):
        with self.assertRaises(ReplayRegistryError):
            self.claim(digest="0")
        self.assertIsNone(self.reg.inspect("sender", "recipient", "message"))

    def test_update_trigger_refuses(self):
        self.claim()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE replay_claims SET package_sha256=?", (self.d2,))

    def test_delete_trigger_refuses(self):
        self.claim()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM replay_claims")

    def test_empty_inspection(self):
        self.assertIsNone(self.reg.inspect("sender", "recipient", "missing"))

    def test_existing_directory_rejected(self):
        with self.assertRaisesRegex(ReplayRegistryError, "INVALID_DATABASE_PATH"):
            DurableReplayRegistry(self.path.parent)

    def test_missing_parent_rejected(self):
        with self.assertRaisesRegex(ReplayRegistryError, "INVALID_DATABASE_PARENT"):
            DurableReplayRegistry(self.path.parent / "missing" / "claims.sqlite")


if __name__ == "__main__":
    unittest.main()
