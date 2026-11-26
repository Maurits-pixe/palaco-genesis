"""Negative tests for independently pinned v7.0 signed checkpoints."""
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_witness_history_v69 import HistoricalHandoffTests, SHA, RUN
from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import serialize
from witness_checkpoint_v70 import sign, verify, inspect


class SignedCheckpointTests(unittest.TestCase):
    def setUp(self):
        HistoricalHandoffTests.setUp(self)
        self.external_key = Ed25519PrivateKey.generate()
        self.external = self.base / "independent-checkpoint.json"
        self.external.write_bytes(sign(self.checkpoint, self.external_key))

    def receive(self, signer=None):
        return inspect(self.bundle, SHA, RUN, self.custodians, self.root,
                       self.witnesses, self.external,
                       signer or self.external_key.public_key())

    def test_signed_checkpoint_pass(self):
        self.assertEqual(self.receive()["authorization"], "DENY")

    def test_wrong_external_signer(self):
        with self.assertRaises(EvidenceRejected):
            self.receive(Ed25519PrivateKey.generate().public_key())

    def test_checkpoint_modified(self):
        body = json.loads(self.external.read_bytes())
        body["sequence"] += 1
        self.external.write_bytes(serialize(body))
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_checkpoint_missing(self):
        self.external.unlink()
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_checkpoint_inside_bundle(self):
        nested = self.bundle / "external.json"
        nested.write_bytes(self.external.read_bytes())
        with self.assertRaises(EvidenceRejected):
            inspect(self.bundle, SHA, RUN, self.custodians, self.root,
                    self.witnesses, nested, self.external_key.public_key())

    def test_older_valid_signed_checkpoint(self):
        old = dict(self.checkpoint)
        old["head"] = "0" * 64
        self.external.write_bytes(sign(old, self.external_key))
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_duplicate_json_key(self):
        self.external.write_bytes(self.external.read_bytes().replace(
            b'"authorization":"DENY"',
            b'"authorization":"DENY","authorization":"ALLOW"'))
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_new_signer_not_self_trusted(self):
        new_signer = Ed25519PrivateKey.generate()
        self.external.write_bytes(sign(self.checkpoint, new_signer))
        with self.assertRaises(EvidenceRejected):
            self.receive()

    def test_signature_round_trip(self):
        self.assertEqual(verify(self.external.read_bytes(),
                                self.external_key.public_key()), self.checkpoint)


if __name__ == "__main__":
    unittest.main()
