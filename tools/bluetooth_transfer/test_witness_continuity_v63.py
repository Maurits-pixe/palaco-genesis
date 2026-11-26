"""v6.3 witness root pin, signer rotation, chain continuity and rollback tests."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import (
    append_incident, append_rotation, check_checkpoint, exercise_ci,
    serialize, snapshot,
)


class WitnessContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "chain.sqlite3"
        self.checkpoint = Path(self.tmp.name) / "checkpoint.json"
        self.root_private = Ed25519PrivateKey.generate()
        self.root = self.root_private.public_key()
        self.next_private = Ed25519PrivateKey.generate()
        self.evidence = json.dumps(valid_record()).encode("utf-8")
        self.other = json.dumps(valid_record(), indent=2).encode("utf-8")

    def prepare(self):
        append_incident(self.db, self.root, self.root_private, self.evidence)
        append_rotation(self.db, self.root, self.root_private, self.next_private.public_key())
        append_incident(self.db, self.root, self.next_private, self.other)
        self.checkpoint.write_bytes(serialize(snapshot(self.db, self.root)))

    def test_three_entries_and_rotation(self):
        self.prepare()
        self.assertEqual(snapshot(self.db, self.root)["sequence"], 3)
        check_checkpoint(self.checkpoint, snapshot(self.db, self.root))

    def test_stale_signing_key_fails(self):
        self.prepare()
        with self.assertRaises(EvidenceRejected):
            append_incident(self.db, self.root, self.root_private, self.evidence)

    def test_duplicate_incident_fails(self):
        self.prepare()
        with self.assertRaises(EvidenceRejected):
            append_incident(self.db, self.root, self.next_private, self.other)

    def test_untrusted_rotation_fails(self):
        append_incident(self.db, self.root, self.root_private, self.evidence)
        with self.assertRaises(EvidenceRejected):
            append_rotation(self.db, self.root, self.next_private, self.root)

    def test_wrong_root_rejected(self):
        self.prepare()
        with self.assertRaises(EvidenceRejected):
            snapshot(self.db, Ed25519PrivateKey.generate().public_key())

    def test_removed_tail_detected_against_checkpoint(self):
        self.prepare()
        with sqlite3.connect(self.db) as con:
            con.execute("DELETE FROM events WHERE seq=3")
            con.execute("DELETE FROM used_incidents WHERE incident_sha256 NOT IN "
                        "(SELECT json_extract(payload, '$.value') FROM events WHERE kind='incident')")
        with self.assertRaises(EvidenceRejected):
            check_checkpoint(self.checkpoint, snapshot(self.db, self.root))

    def test_forged_checkpoint_rejected(self):
        self.prepare()
        fake = snapshot(self.db, self.root)
        fake["head"] = "a" * 64
        self.checkpoint.write_bytes(serialize(fake))
        with self.assertRaises(EvidenceRejected):
            check_checkpoint(self.checkpoint, snapshot(self.db, self.root))

    def test_missing_checkpoint_rejected(self):
        self.prepare()
        self.checkpoint.unlink()
        with self.assertRaises(EvidenceRejected):
            check_checkpoint(self.checkpoint, snapshot(self.db, self.root))

    def test_missing_middle_row_rejected(self):
        self.prepare()
        with sqlite3.connect(self.db) as con:
            con.execute("DELETE FROM events WHERE seq=2")
        with self.assertRaises(EvidenceRejected):
            snapshot(self.db, self.root)

    def test_tampered_rotation_rejected(self):
        self.prepare()
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE events SET previous=? WHERE seq=2", ("a" * 64,))
        with self.assertRaises(EvidenceRejected):
            snapshot(self.db, self.root)

    def test_ci_smoke(self):
        self.assertTrue(exercise_ci(self.evidence))


if __name__ == "__main__":
    unittest.main()
