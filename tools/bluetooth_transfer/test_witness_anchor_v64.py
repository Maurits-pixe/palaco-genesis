"""PALACO v6.4 external witness negative-path tests, CI only."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_anchor_v64 import (
    envelope, exercise_ci, sign_checkpoint, verify_checkpoint,
    verify_external, write_once,
)
from witness_continuity_v63 import (
    append_incident, append_rotation, public_id, serialize, snapshot,
)


class ExternalWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        self.ledger = folder / "events.sqlite"
        self.checkpoint = folder / "external.json"
        self.producer = Ed25519PrivateKey.generate()
        self.witness = Ed25519PrivateKey.generate()
        self.trusted_root = self.producer.public_key()
        self.trusted_witness = self.witness.public_key()
        self.evidence = json.dumps(valid_record()).encode("utf-8")
        append_incident(self.ledger, self.trusted_root, self.producer, self.evidence)
        self.state = snapshot(self.ledger, self.trusted_root)
        write_once(self.checkpoint, sign_checkpoint(self.state, self.witness))

    def test_valid_independent_signature(self):
        verify_external(self.ledger, self.checkpoint, self.trusted_root, self.trusted_witness)

    def test_wrong_witness_root_rejected(self):
        with self.assertRaises(EvidenceRejected):
            verify_external(self.ledger, self.checkpoint, self.trusted_root,
                            Ed25519PrivateKey.generate().public_key())

    def test_missing_checkpoint_rejected(self):
        self.checkpoint.unlink()
        with self.assertRaises(EvidenceRejected):
            verify_external(self.ledger, self.checkpoint, self.trusted_root, self.trusted_witness)

    def test_untrusted_signature_rejected(self):
        forged = sign_checkpoint(self.state, Ed25519PrivateKey.generate())
        self.checkpoint.write_bytes(forged)
        with self.assertRaises(EvidenceRejected):
            verify_external(self.ledger, self.checkpoint, self.trusted_root, self.trusted_witness)

    def test_tampered_checkpoint_rejected(self):
        obj = json.loads(self.checkpoint.read_text())
        obj["authorization"] = "ALLOW"
        self.checkpoint.write_bytes(serialize(obj))
        with self.assertRaises(EvidenceRejected):
            verify_external(self.ledger, self.checkpoint, self.trusted_root, self.trusted_witness)

    def test_duplicate_checkpoint_field_rejected(self):
        raw = self.checkpoint.read_text()
        raw = raw.replace('"authorization":"DENY"', '"authorization":"DENY","authorization":"ALLOW"')
        self.checkpoint.write_text(raw)
        with self.assertRaises(EvidenceRejected):
            verify_external(self.ledger, self.checkpoint, self.trusted_root, self.trusted_witness)

    def test_checkpoint_cannot_be_overwritten(self):
        with self.assertRaises(FileExistsError):
            write_once(self.checkpoint, b"replacement")

    def test_joint_truncation_and_checkpoint_rewrite_rejected(self):
        with sqlite3.connect(self.ledger) as con:
            con.execute("DELETE FROM events")
            con.execute("DELETE FROM used_incidents")
        forged = envelope({"sequence": 1, "head": "a"*64, "root_id": public_id(self.trusted_root)},
                          public_id(self.trusted_witness))
        forged["signature"] = "AA=="
        self.checkpoint.write_bytes(serialize(forged))
        with self.assertRaises(EvidenceRejected):
            verify_external(self.ledger, self.checkpoint, self.trusted_root, self.trusted_witness)

    def test_ci_three_entry_rollback_challenge(self):
        self.assertTrue(exercise_ci(self.evidence))


if __name__ == "__main__":
    unittest.main()
