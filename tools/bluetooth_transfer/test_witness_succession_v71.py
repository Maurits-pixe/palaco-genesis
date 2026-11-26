"""v7.1 tests: externally pinned checkpoint successor and negative paths."""
import json
import unittest
from pathlib import Path

from witness_continuity_v63 import append_incident, snapshot, public_id
from witness_archive_v66 import build_archive, channel_path
from witness_anchor_v64 import sign_checkpoint as sign_witness, write_once
from witness_custody_v67 import sign as sign_custody
from witness_history_v69 import prepare as prepare_history

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
        old = self.checkpoint.copy()
        self.prior = sign_checkpoint(old, self.signer)

        # Build a REAL two-event successor ledger and signed witness manifest.
        # Distinct whitespace encoding represents a separate valid incident.
        second = json.dumps(json.loads(self.incident), indent=2).encode("utf-8")
        append_incident(self.source, self.root, self.root_private, second)
        self.checkpoint = snapshot(self.source, self.root)
        witness_private = [Ed25519PrivateKey.generate() for _ in range(3)]
        ordered = sorted((public_id(k.public_key()), k) for k in witness_private)
        self.witnesses = {ident: key.public_key() for ident, key in ordered}
        channels = self.base / "channels-v71"
        for i, (_, key) in enumerate(ordered[:2]):
            target = channel_path(channels, i)
            target.parent.mkdir(parents=True)
            write_once(target, sign_witness(self.checkpoint, key))
        manifest = self.base / "manifest-v71.json"
        build_archive(self.source, self.root, self.witnesses, channels,
                      manifest, ("received", "received", "absent"))
        m = manifest.read_bytes()
        custody_private = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.custodians = {public_id(k.public_key()): k.public_key()
                          for k in custody_private}
        receipts = (sign_custody(m, SHA, RUN, custody_private[0]),
                    sign_custody(m, SHA, RUN, custody_private[1]))
        self.bundle = self.base / "bundle-v71"
        prepare_history(self.bundle, self.source, channels, second, m, receipts,
                        SHA, RUN, self.root, self.witnesses)
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
            sign_successor(self.prior, {"sequence": 1, "head": "b" * 64,
                           "root_id": self.checkpoint["root_id"]}, self.signer)

    def test_root_swap(self):
        with self.assertRaises(EvidenceRejected):
            sign_successor(self.prior, {"sequence": 2, "head": "b" * 64,
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
            self.prior, {"sequence": 2, "head": "f" * 64,
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
