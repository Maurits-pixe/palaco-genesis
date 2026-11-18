"""v22 checkpoint anchor regression fixtures: NOT external trust providers."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import unittest

from distributed_replay_v18 import candidate, receipt_statement, RECEIPT_SCHEMA
from monotonic_authority_checkpoints_v21 import GENESIS, checkpoint_candidate
from durable_checkpoint_anchor_v22 import AnchorError, DurableCheckpointAnchor


class AnchorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "separate-anchor.sqlite"
        self.anchor = DurableCheckpointAnchor(self.path)
        self.claims = [
            candidate("sender", "recipient", "one", "a"*64, "phone"),
            candidate("sender", "recipient", "two", "b"*64, "tablet")]
        self.receipts = [{
            "schema": RECEIPT_SCHEMA, "authority_sequence": n,
            "decision": "first-claim", "proof": "synthetic-proof-" + str(n)}
            for n in (1, 2)]
        self.verify_receipt = lambda *_: True
        self.authorize_publish = lambda *_: True

    def advance(self, length=1, *, expected_sequence=0, expected_head=GENESIS,
                **kw):
        args = dict(verify_receipt=self.verify_receipt,
                    authorize_publish=self.authorize_publish)
        args.update(kw)
        return self.anchor.advance(
            self.claims[:length], self.receipts[:length],
            expected_sequence=expected_sequence,
            expected_head=expected_head, **args)

    def test_first_checkpoint(self):
        report = self.advance()
        self.assertEqual(report["sequence"], 1)
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_restart_preserves(self):
        report = self.advance()
        self.assertEqual(DurableCheckpointAnchor(self.path).current(),
                         (1, report["head"]))

    def test_second_sequence_contiguous(self):
        first = self.advance()
        second = self.advance(2, expected_sequence=1, expected_head=first["head"])
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(self.anchor.current(), (2, second["head"]))

    def test_stale_cas(self):
        self.advance()
        with self.assertRaisesRegex(AnchorError, "STALE_CHECKPOINT"):
            self.advance()

    def test_concurrent_only_one_winner(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.advance) for _ in range(2)]
            outcomes = []
            for f in futures:
                try:
                    outcomes.append(f.result())
                except AnchorError as exc:
                    outcomes.append(str(exc))
        self.assertEqual(sum(type(x) is dict for x in outcomes), 1)
        self.assertIn("STALE_CHECKPOINT", outcomes)

    def test_noncontiguous_input(self):
        with self.assertRaisesRegex(AnchorError, "NONCONTIGUOUS_ADVANCE"):
            self.advance(2)

    def test_modified_prefix_rejected(self):
        first = self.advance()
        saved = self.claims[0]
        self.claims[0] = dict(saved, package_sha256="f"*64)
        with self.assertRaisesRegex(AnchorError, "HISTORY_PREFIX_MISMATCH"):
            self.advance(2, expected_sequence=1, expected_head=first["head"])

    def test_broken_receipt_rejected(self):
        self.receipts[0]["decision"] = "duplicate"
        with self.assertRaisesRegex(AnchorError, "UNVERIFIED_HISTORY"):
            self.advance()

    def test_bad_signature_rejected(self):
        with self.assertRaisesRegex(AnchorError, "UNVERIFIED_HISTORY"):
            self.advance(verify_receipt=lambda *_: False)

    def test_nonboolean_signature_rejected(self):
        with self.assertRaisesRegex(AnchorError, "UNVERIFIED_HISTORY"):
            self.advance(verify_receipt=lambda *_: 1)

    def test_missing_signature_verifier(self):
        with self.assertRaisesRegex(AnchorError, "EXTERNAL_POLICY_REQUIRED"):
            self.advance(verify_receipt=None)

    def test_publish_policy_denied(self):
        with self.assertRaisesRegex(AnchorError, "PUBLISH_DENIED"):
            self.advance(authorize_publish=lambda *_: False)
        self.assertEqual(self.anchor.current(), (0, GENESIS))

    def test_publish_policy_nonboolean(self):
        with self.assertRaisesRegex(AnchorError, "PUBLISH_DENIED"):
            self.advance(authorize_publish=lambda *_: 1)

    def test_publish_policy_exception(self):
        def unavailable(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(AnchorError, "PUBLISH_POLICY_UNAVAILABLE"):
            self.advance(authorize_publish=unavailable)

    def test_missing_publish_policy(self):
        with self.assertRaisesRegex(AnchorError, "EXTERNAL_POLICY_REQUIRED"):
            self.advance(authorize_publish=None)

    def test_empty_anchor_not_trusted(self):
        with self.assertRaisesRegex(AnchorError, "EMPTY_ANCHOR_NOT_TRUSTED"):
            self.anchor.inspect(independently_verify_anchor=lambda *_: True)

    def test_missing_external_anchor(self):
        self.advance()
        with self.assertRaisesRegex(AnchorError, "EXTERNAL_ANCHOR_REQUIRED"):
            self.anchor.inspect(independently_verify_anchor=None)

    def test_external_anchor_denied(self):
        self.advance()
        with self.assertRaisesRegex(AnchorError, "UNTRUSTED_ANCHOR"):
            self.anchor.inspect(independently_verify_anchor=lambda *_: False)

    def test_external_anchor_nonboolean(self):
        self.advance()
        with self.assertRaisesRegex(AnchorError, "UNTRUSTED_ANCHOR"):
            self.anchor.inspect(independently_verify_anchor=lambda *_: 1)

    def test_external_anchor_exception(self):
        self.advance()
        def unavailable(*_):
            raise ConnectionError("external offline")
        with self.assertRaisesRegex(AnchorError, "EXTERNAL_ANCHOR_UNAVAILABLE"):
            self.anchor.inspect(independently_verify_anchor=unavailable)

    def test_synthetic_external_match(self):
        report = self.advance()
        trusted = (report["sequence"], report["head"])
        self.assertEqual(self.anchor.inspect(
            independently_verify_anchor=lambda n, h: (n, h) == trusted), trusted)

    def test_mutation_triggers(self):
        self.advance()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE anchored_checkpoints SET head=?", ("0"*64,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM anchored_checkpoints")

    def test_modified_checkpoint_detected(self):
        self.advance()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER anchor_no_update")
            db.execute("UPDATE anchored_checkpoints SET previous=? WHERE sequence=1",
                       ("0"*64,))
        with self.assertRaisesRegex(AnchorError, "CORRUPT_CHECKPOINT_CHAIN"):
            self.anchor.current()


if __name__ == "__main__":
    unittest.main()
