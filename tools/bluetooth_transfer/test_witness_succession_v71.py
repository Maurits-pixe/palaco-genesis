"""v7.1 tests: externally pinned checkpoint successor and negative paths."""
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_witness_history_v69 import HistoricalHandoffTests, SHA, RUN
from verify_scm_ci_incident import EvidenceRejected
from witness_checkpoint_v70 import sign as sign_checkpoint
from witness_continuity_v63 import serialize
from witness_succession_v71 import (
    digest, inspect, sign_successor, verify_successor,
)


class SuccessionTests(unittest.TestCase):
    def setUp(self):
        HistoricalHandoffTests.setUp(self)
        self.signer = Ed25519PrivateKey.generate()
        old = {"sequence": self.checkpoint["sequence"] - 1,
               "head": "0" * 64, "root_id": self.checkpoint["root_id"]}
        self.prior = sign_checkpoint(old, self.signer)
        self.successor = sign_successor(self.prior, self.checkpoint, self.signer)
        self.prior_path = self.base / "trusted-prior.json"
        self.next_path = self.base / "trusted-successor.json"
        self.prior_path.write_bytes(self.prior)
        self.next_path.write_bytes(self.successor)
        self.latest = digest(self.successor)

    def verify(self, latest=None):
        return verify_successor(self.prior, self.successor,
                                self.signer.public_key(),
                                self.latest if latest is None else latest)

    def receive(self, latest=None):
        return inspect(self.bundle, SHA, RUN, self.custodians,
                       self.root, self.witnesses, self.prior_path,
                       self.next_path, self.signer.public_key(),
                       self.latest if latest is None else latest)

    def test_signed_succession(self):
        self.assertEqual(self.verify(), self.checkpoint)

    def test_receiver_full_history(self):
        self.assertEqual(self.receive()["authorization"], "DENY")

    def test_older_digest_rejected(self):
        with self.assertRaises(EvidenceRejected):
            self.verify(digest(self.prior))

    def test_missing_latest_digest_rejected(self):
        with self.assertRaises(EvidenceRejected):
            self.verify("")

    def test_wrong_signer(self):
        with self.assertRaises(EvidenceRejected):
            verify_successor(self.prior, self.successor,
                             Ed25519PrivateKey.generate().public_key(),
                             self.latest)

    def test_tampered_signature(self):
        doc = json.loads(self.successor)
        doc["signature"] = "AA=="
        changed = serialize(doc)
        with self.assertRaises(EvidenceRejected):
            verify_successor(self.prior, changed, self.signer.public_key(),
                             digest(changed))

    def test_tampered_previous_hash(self):
        doc = json.loads(self.successor)
        doc["prior_sha256"] = "a" * 64
        changed = serialize(doc)
        with self.assertRaises(EvidenceRejected):
            verify_successor(self.prior, changed, self.signer.public_key(),
                             digest(changed))

    def test_nonadvancing_sequence(self):
        with self.assertRaises(EvidenceRejected):
            sign_successor(self.prior, {"sequence": 0, "head": "b" * 64,
                           "root_id": self.checkpoint["root_id"]}, self.signer)

    def test_root_swap(self):
        with self.assertRaises(EvidenceRejected):
            sign_successor(self.prior, {"sequence": 1, "head": "b" * 64,
                           "root_id": "f" * 64}, self.signer)

    def test_missing_external_record(self):
        self.next_path.unlink()
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_external_record_inside_bundle(self):
        self.next_path = self.bundle / "successor.json"
        self.next_path.write_bytes(self.successor)
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_receiver_denies_wrong_current_head(self):
        self.next_path.write_bytes(sign_successor(
            self.prior, {"sequence": 1, "head": "f" * 64,
                         "root_id": self.checkpoint["root_id"]}, self.signer))
        with self.assertRaises(EvidenceRejected):
            self.receive(digest(self.next_path.read_bytes()))

    def test_duplicate_fields_rejected(self):
        changed = self.successor.replace(
            b'"authorization":"DENY"',
            b'"authorization":"DENY","authorization":"ALLOW"')
        with self.assertRaises(EvidenceRejected):
            verify_successor(self.prior, changed, self.signer.public_key(),
                             digest(changed))


if __name__ == "__main__":
    unittest.main()
