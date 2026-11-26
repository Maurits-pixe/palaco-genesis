"""v6.5 regression tests for pinned 2-of-3 independent checkpoint witnesses."""
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_anchor_v64 import sign_checkpoint, write_once
from witness_continuity_v63 import append_incident, public_id, snapshot
from witness_quorum_v65 import exercise_ci, verify_quorum


class QuorumTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.ledger = folder / "ledger.sqlite3"
        self.root_signer = Ed25519PrivateKey.generate()
        self.root = self.root_signer.public_key()
        self.witnesses = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.pinned = {public_id(s.public_key()): s.public_key() for s in self.witnesses}
        self.paths = [folder / f"witness-{index}.json" for index in range(3)]
        self.evidence = json.dumps(valid_record()).encode("utf-8")
        append_incident(self.ledger, self.root, self.root_signer, self.evidence)
        self.state = snapshot(self.ledger, self.root)
        for path, signer in zip(self.paths, self.witnesses):
            write_once(path, sign_checkpoint(self.state, signer))

    def check(self, paths=None, pinned=None):
        verify_quorum(self.ledger, self.root, self.pinned if pinned is None else pinned,
                      self.paths if paths is None else paths)

    def test_all_three_pass(self):
        self.check()

    def test_two_of_three_pass(self):
        self.check(self.paths[:2])

    def test_only_one_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check(self.paths[:1])

    def test_no_receipts_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check([])

    def test_duplicate_endorsement_denied(self):
        self.paths[1].write_bytes(self.paths[0].read_bytes())
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_duplicate_path_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check([self.paths[0], self.paths[0]])

    def test_unknown_witness_denied(self):
        other = Ed25519PrivateKey.generate()
        self.paths[2].write_bytes(sign_checkpoint(self.state, other))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_tampered_signature_denied_even_with_two_valid(self):
        record = json.loads(self.paths[2].read_text())
        record["signature"] = "AA=="
        self.paths[2].write_text(json.dumps(record))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_signed_split_view_denied_even_with_two_valid(self):
        different = dict(self.state)
        different["head"] = "a" * 64
        self.paths[2].write_bytes(sign_checkpoint(different, self.witnesses[2]))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_missing_file_denied(self):
        self.paths[2].unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_changed_pin_denied(self):
        pinned = dict(self.pinned)
        key = next(iter(pinned))
        pinned[key] = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(EvidenceRejected):
            self.check(pinned=pinned)

    def test_incomplete_pin_roster_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check(pinned=dict(list(self.pinned.items())[:2]))

    def test_ledger_mutation_denied(self):
        self.ledger.unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_live_smoke(self):
        self.assertTrue(exercise_ci(self.evidence))


if __name__ == "__main__":
    unittest.main()
