"""PALACO v6.9 full-history transfer negative regressions."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_anchor_v64 import sign_checkpoint, write_once
from witness_archive_v66 import build_archive, channel_path
from witness_continuity_v63 import append_incident, public_id, serialize, snapshot
from witness_custody_v67 import sign
from witness_history_v69 import prepare, inspect

SHA = "a" * 40
RUN = "2345678"


class HistoricalHandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / "source.sqlite3"
        self.channels = self.base / "channels"
        self.bundle = self.base / "bundle"
        self.root_private = Ed25519PrivateKey.generate()
        self.root = self.root_private.public_key()
        self.incident = json.dumps(valid_record()).encode()
        append_incident(self.source, self.root, self.root_private, self.incident)
        self.checkpoint = snapshot(self.source, self.root)
        witness_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        ordered = sorted((public_id(k.public_key()), k) for k in witness_keys)
        self.witnesses = {ident: private.public_key() for ident, private in ordered}
        for i, (_, private) in enumerate(ordered[:2]):
            path = channel_path(self.channels, i)
            path.parent.mkdir(parents=True)
            write_once(path, sign_checkpoint(self.checkpoint, private))
        manifest = self.base / "manifest.json"
        build_archive(self.source, self.root, self.witnesses, self.channels,
                      manifest, ("received", "received", "absent"))
        data = manifest.read_bytes()
        custodian_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.custodians = {public_id(k.public_key()): k.public_key() for k in custodian_keys}
        receipts = (sign(data, SHA, RUN, custodian_keys[0]),
                    sign(data, SHA, RUN, custodian_keys[1]))
        prepare(self.bundle, self.source, self.channels, self.incident,
                data, receipts, SHA, RUN, self.root, self.witnesses)

    def check(self, checkpoint=None):
        return inspect(self.bundle, SHA, RUN, self.custodians, self.root,
                       self.witnesses, self.checkpoint if checkpoint is None else checkpoint)

    def test_valid_complete_history(self):
        self.assertEqual(self.check()["authorization"], "DENY")

    def test_missing_ledger(self):
        (self.bundle / "ledger.sqlite3").unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_missing_witness(self):
        (self.bundle / "channel-0.json").unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_changed_witness(self):
        file = self.bundle / "channel-1.json"
        file.write_bytes(file.read_bytes() + b" ")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_wrong_external_checkpoint(self):
        older = dict(self.checkpoint)
        older["sequence"] = 0
        with self.assertRaises(EvidenceRejected):
            self.check(older)

    def test_no_external_checkpoint(self):
        with self.assertRaises(EvidenceRejected):
            inspect(self.bundle, SHA, RUN, self.custodians, self.root,
                    self.witnesses, None)

    def test_untrusted_chain_root(self):
        with self.assertRaises(EvidenceRejected):
            inspect(self.bundle, SHA, RUN, self.custodians,
                    Ed25519PrivateKey.generate().public_key(),
                    self.witnesses, self.checkpoint)

    def test_missing_history_event_rejected(self):
        ledger = self.bundle / "ledger.sqlite3"
        with sqlite3.connect(ledger) as db:
            db.execute("DELETE FROM events WHERE seq=1")
            db.execute("DELETE FROM used_incidents")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_malformed_index(self):
        file = self.bundle / "history-index.json"
        file.write_bytes(file.read_bytes().replace(
            b'"authorization":"DENY"', b'"authorization":"ALLOW"'))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_nested_extra_file(self):
        (self.bundle / "unexpected").write_text("x")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_wrong_run(self):
        with self.assertRaises(EvidenceRejected):
            inspect(self.bundle, SHA, "2345679", self.custodians, self.root,
                    self.witnesses, self.checkpoint)


if __name__ == "__main__":
    unittest.main()
