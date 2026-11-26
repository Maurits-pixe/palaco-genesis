"""v7.2 atomic checkpoint succession register positive and negative tests."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verify_scm_ci_incident import EvidenceRejected
from witness_checkpoint_v70 import sign as sign_checkpoint
from witness_succession_v71 import digest, sign_successor
from witness_register_v72 import initialize, state, advance


class RegisterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.register = self.directory / "checkpoint.sqlite3"
        self.signer = Ed25519PrivateKey.generate()
        self.root_id = "a" * 64
        self.prior_state = {"sequence": 1, "head": "b" * 64,
                            "root_id": self.root_id}
        self.next_state = {"sequence": 2, "head": "c" * 64,
                           "root_id": self.root_id}
        self.prior = sign_checkpoint(self.prior_state, self.signer)
        self.successor = sign_successor(self.prior, self.next_state, self.signer)
        self.anchor = digest(self.prior)
        initialize(self.register, self.prior, self.signer.public_key(), self.anchor)

    def advance(self, prior=None, successor=None, anchor=None, signer=None):
        return advance(self.register, prior or self.prior,
                       successor or self.successor,
                       signer or self.signer.public_key(),
                       self.anchor if anchor is None else anchor)

    def test_initial_state(self):
        self.assertEqual(state(self.register, self.anchor)["generation"], 0)

    def test_valid_atomic_advance(self):
        updated = self.advance()
        self.assertEqual(updated["generation"], 1)
        self.assertEqual(updated["sequence"], 2)
        self.assertEqual(updated["authorization"], "DENY")

    def test_replay_rejected(self):
        self.advance()
        with self.assertRaises(EvidenceRejected):
            self.advance()

    def test_competing_successor_rejected(self):
        competitor = sign_successor(
            self.prior, {"sequence": 2, "head": "d" * 64,
                         "root_id": self.root_id}, self.signer)
        self.advance()
        with self.assertRaises(EvidenceRejected):
            self.advance(successor=competitor)

    def test_stale_external_anchor_rejected_after_advance(self):
        self.advance()
        with self.assertRaises(EvidenceRejected):
            state(self.register, self.anchor)

    def test_wrong_initial_anchor_rejected(self):
        with self.assertRaises(EvidenceRejected):
            initialize(self.directory / "other.sqlite3", self.prior,
                       self.signer.public_key(), "f" * 64)

    def test_no_overwrite_register(self):
        with self.assertRaises(EvidenceRejected):
            initialize(self.register, self.prior,
                       self.signer.public_key(), self.anchor)

    def test_untrusted_successor_signer(self):
        with self.assertRaises(EvidenceRejected):
            self.advance(signer=Ed25519PrivateKey.generate().public_key())

    def test_old_or_wrong_expected_anchor(self):
        with self.assertRaises(EvidenceRejected):
            self.advance(anchor="f" * 64)

    def test_missing_transition_detected(self):
        current = self.advance()
        with sqlite3.connect(self.register) as connection:
            connection.execute("DELETE FROM transitions")
        with self.assertRaises(EvidenceRejected):
            state(self.register, current["latest_digest"])

    def test_mutated_transition_detected(self):
        current = self.advance()
        with sqlite3.connect(self.register) as connection:
            connection.execute("UPDATE transitions SET successor=x'0102'")
        with self.assertRaises(EvidenceRejected):
            state(self.register, current["latest_digest"])

    def test_rolled_back_register_detected_by_external_anchor(self):
        backup = self.directory / "old.sqlite3"
        backup.write_bytes(self.register.read_bytes())
        current = self.advance()
        self.register.write_bytes(backup.read_bytes())
        with self.assertRaises(EvidenceRejected):
            state(self.register, current["latest_digest"])

    def test_symlink_register_rejected(self):
        alias = self.directory / "alias.sqlite3"
        alias.symlink_to(self.register)
        with self.assertRaises(EvidenceRejected):
            state(alias, self.anchor)

    def test_unsigned_successor_rejected(self):
        with self.assertRaises(EvidenceRejected):
            self.advance(successor=json.dumps({"sequence": 2}).encode())


if __name__ == "__main__":
    unittest.main()
