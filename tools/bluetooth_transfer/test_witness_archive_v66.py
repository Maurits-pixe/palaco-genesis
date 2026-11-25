"""v6.6 channel-delivery archive negative-path regressions."""
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_anchor_v64 import sign_checkpoint, write_once
from witness_archive_v66 import (
    build_archive, channel_path, exercise_ci, verify_archive,
)
from witness_continuity_v63 import append_incident, public_id, serialize, snapshot


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.ledger = base / "events.sqlite3"
        self.channels = base / "channels"
        self.manifest = base / "manifest.json"
        self.signer = Ed25519PrivateKey.generate()
        self.evidence = json.dumps(valid_record()).encode()
        append_incident(self.ledger, self.signer.public_key(), self.signer, self.evidence)
        self.state = snapshot(self.ledger, self.signer.public_key())
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.ordered = sorted((public_id(key.public_key()), key) for key in keys)
        self.pinned = {wid: key.public_key() for wid, key in self.ordered}

    def put(self, index, state=None):
        path = channel_path(self.channels, index)
        path.parent.mkdir(exist_ok=True, parents=True)
        write_once(path, sign_checkpoint(self.state if state is None else state,
                                         self.ordered[index][1]))
        return path

    def build(self, statuses):
        build_archive(self.ledger, self.signer.public_key(), self.pinned,
                      self.channels, self.manifest, statuses)

    def check(self):
        verify_archive(self.ledger, self.signer.public_key(), self.pinned,
                       self.channels, self.manifest)

    def test_two_witnesses_one_absent_pass(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        self.check()

    def test_three_witnesses_pass(self):
        for i in range(3):
            self.put(i)
        self.build(("received", "received", "received"))
        self.check()

    def test_single_witness_denied(self):
        self.put(0)
        self.build(("received", "absent", "absent"))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_pending_delivery_denied(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "pending"))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_late_receipt_denied(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        self.put(2)
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_deleted_receipt_denied(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        channel_path(self.channels, 0).unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_tampered_receipt_denied(self):
        path = self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_signed_split_view_cannot_be_archived(self):
        self.put(0)
        self.put(1)
        other = dict(self.state)
        other["head"] = "f" * 64
        self.put(2, other)
        with self.assertRaises(EvidenceRejected):
            self.build(("received", "received", "received"))

    def test_manifest_tamper_denied(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        record = json.loads(self.manifest.read_text())
        record["witnesses"][0]["state"] = "absent"
        self.manifest.write_bytes(serialize(record))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_changed_roster_denied(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        replacement = dict(self.pinned)
        first = next(iter(replacement))
        replacement[first] = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(EvidenceRejected):
            verify_archive(self.ledger, self.signer.public_key(), replacement,
                           self.channels, self.manifest)

    def test_manifest_rewrite_denied(self):
        self.put(0)
        self.put(1)
        self.build(("received", "received", "absent"))
        with self.assertRaises(EvidenceRejected):
            self.build(("received", "received", "absent"))

    def test_missing_received_file_denied_during_archive(self):
        self.put(0)
        with self.assertRaises(EvidenceRejected):
            self.build(("received", "received", "absent"))

    def test_ci_smoke(self):
        self.assertTrue(exercise_ci(self.evidence))


if __name__ == "__main__":
    unittest.main()
