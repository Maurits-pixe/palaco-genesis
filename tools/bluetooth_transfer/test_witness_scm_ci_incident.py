"""Negative-path tests: ephemeral Ed25519 witness, fixed HOLD, SQLite ledger."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_scm_ci_incident import attest, verify


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "incident.json"
        self.ledger = self.root / "incidents.sqlite3"
        self.receipt = self.root / "witness.json"
        self.public = self.root / "witness.pub"
        self.evidence.write_text(json.dumps(valid_record()), encoding="utf-8")

    def attest(self):
        attest(self.evidence, self.ledger, self.receipt, self.public)

    def verify(self):
        verify(self.evidence, self.ledger, self.receipt, self.public)

    def test_round_trip_and_replay_refused(self):
        self.attest()
        self.verify()
        with self.assertRaises(EvidenceRejected):
            self.attest()

    def test_absent_witness_rejected(self):
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_incident_mutation_rejected(self):
        self.attest()
        document = json.loads(self.evidence.read_text(encoding="utf-8"))
        document["authorization"] = "ALLOW"
        self.evidence.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_signature_mutation_rejected(self):
        self.attest()
        document = json.loads(self.receipt.read_text(encoding="utf-8"))
        document["signature"] = "AA=="
        self.receipt.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_wrong_public_key_rejected(self):
        self.attest()
        self.public.write_bytes(b"\x01" * 32)
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_missing_registry_rejected(self):
        self.attest()
        self.ledger.unlink()
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_missing_registry_row_rejected(self):
        self.attest()
        with sqlite3.connect(self.ledger) as con:
            con.execute("DELETE FROM entries")
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_hash_chain_corruption_rejected(self):
        self.attest()
        with sqlite3.connect(self.ledger) as con:
            con.execute("UPDATE entries SET previous_hash=? WHERE seq=1", ("a" * 64,))
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_missing_receipt_rejected(self):
        self.attest()
        self.receipt.unlink()
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_extra_receipt_field_rejected(self):
        self.attest()
        document = json.loads(self.receipt.read_text(encoding="utf-8"))
        document["permission"] = "ALLOW"
        self.receipt.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(EvidenceRejected):
            self.verify()


if __name__ == "__main__":
    unittest.main()
