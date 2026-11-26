"""v7.3 full checkpoint-history replay, fork/rollback and atomic append tests."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verify_scm_ci_incident import EvidenceRejected
from witness_checkpoint_v70 import sign as sign_genesis
from witness_multigeneration_v73 import (
    digest, sign, verify, initialize, advance, inspect,
)


class MultiGenerationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "checkpoints.sqlite3"
        self.signer = Ed25519PrivateKey.generate()
        self.root = "a" * 64
        self.initial_state = {"sequence": 1, "head": "b" * 64,
                              "root_id": self.root}
        self.genesis = sign_genesis(self.initial_state, self.signer)
        self.anchor = digest(self.genesis)
        initialize(self.path, self.genesis, self.signer.public_key(), self.anchor)
        self.latest = self.anchor
        self.raw = self.genesis
        self.current = self.initial_state

    def append(self, head, seq=None):
        next_state = {"sequence": seq if seq is not None else self.current["sequence"] + 1,
                      "head": head, "root_id": self.root}
        generation = self.current_generation() + 1
        successor = sign(self.raw, self.current, generation,
                         next_state, self.signer)
        result = advance(self.path, successor, self.signer.public_key(),
                         self.anchor, self.latest)
        self.raw = successor
        self.latest = digest(successor)
        self.current = next_state
        return result

    def current_generation(self):
        return inspect(self.path, self.signer.public_key(),
                       self.anchor, self.latest)["generation"]

    def check(self, latest=None, signer=None):
        return inspect(self.path, signer or self.signer.public_key(),
                       self.anchor, self.latest if latest is None else latest)

    def test_genesis_only(self):
        self.assertEqual(self.check()["generation"], 0)

    def test_three_generations_replay(self):
        self.append("c" * 64)
        self.append("d" * 64)
        result = self.append("e" * 64)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(self.check()["sequence"], 4)
        self.assertEqual(self.check()["authorization"], "DENY")

    def test_stale_anchor_prevents_second_writer(self):
        original = self.latest
        self.append("c" * 64)
        competitor = sign(self.genesis, self.initial_state, 1,
                          {"sequence": 2, "head": "d" * 64, "root_id": self.root},
                          self.signer)
        with self.assertRaises(EvidenceRejected):
            advance(self.path, competitor, self.signer.public_key(),
                    self.anchor, original)

    def test_replay_previously_signed_entry(self):
        self.append("c" * 64)
        with self.assertRaises(EvidenceRejected):
            advance(self.path, self.raw, self.signer.public_key(),
                    self.anchor, self.latest)

    def test_delete_middle_generation(self):
        self.append("c" * 64)
        self.append("d" * 64)
        self.append("e" * 64)
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM checkpoint_events WHERE generation=2")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_modified_historical_signature(self):
        self.append("c" * 64)
        self.append("d" * 64)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE checkpoint_events SET raw=x'0102' WHERE generation=1")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_modified_historical_previous_digest(self):
        self.append("c" * 64)
        self.append("d" * 64)
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT raw FROM checkpoint_events WHERE generation=2").fetchone()[0]
            modified = json.loads(row)
            modified["previous_digest"] = "0" * 64
            db.execute("UPDATE checkpoint_events SET raw=? WHERE generation=2",
                       (json.dumps(modified).encode(),))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_external_latest_digest_detects_whole_db_restore(self):
        archive = self.path.read_bytes()
        self.append("c" * 64)
        self.path.write_bytes(archive)
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_wrong_signer_denied(self):
        self.append("c" * 64)
        with self.assertRaises(EvidenceRejected):
            self.check(signer=Ed25519PrivateKey.generate().public_key())

    def test_root_swap_denied(self):
        with self.assertRaises(EvidenceRejected):
            sign(self.genesis, self.initial_state, 1,
                 {"sequence": 2, "head": "c" * 64, "root_id": "f" * 64},
                 self.signer)

    def test_same_sequence_denied(self):
        with self.assertRaises(EvidenceRejected):
            sign(self.genesis, self.initial_state, 1,
                 {"sequence": 1, "head": "c" * 64, "root_id": self.root},
                 self.signer)

    def test_genesis_substitution_denied(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE checkpoint_genesis SET raw=x'0102'")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_missing_genesis_denied(self):
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM checkpoint_genesis")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_duplicate_fields_denied(self):
        entry = sign(self.genesis, self.initial_state, 1,
                     {"sequence": 2, "head": "c" * 64, "root_id": self.root},
                     self.signer)
        duplicated = entry.replace(
            b'"authorization":"DENY"',
            b'"authorization":"DENY","authorization":"ALLOW"')
        with self.assertRaises(EvidenceRejected):
            verify(self.genesis, self.initial_state, 1, duplicated,
                   self.signer.public_key())

    def test_no_overwrite(self):
        with self.assertRaises(EvidenceRejected):
            initialize(self.path, self.genesis, self.signer.public_key(),
                       self.anchor)

    def test_extra_unexpected_generation(self):
        self.append("c" * 64)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO checkpoint_events VALUES (9,x'0102')")
        with self.assertRaises(EvidenceRejected):
            self.check()


if __name__ == "__main__":
    unittest.main()
