"""v6.8 transferable evidence handoff regression tests."""
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_custody_v67 import sign
from witness_continuity_v63 import public_id, serialize
from witness_handoff_v68 import prepare, inspect, exercise_ci

SHA = "a" * 40
RUN = "2345678"


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name) / "handoff"
        self.incident = json.dumps(valid_record()).encode()
        self.manifest = serialize({"decision": "HOLD", "authorization": "DENY"})
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.trusted = {public_id(k.public_key()): k.public_key() for k in self.keys}
        self.receipts = (sign(self.manifest, SHA, RUN, self.keys[0]),
                         sign(self.manifest, SHA, RUN, self.keys[1]))
        prepare(self.dir, self.incident, self.manifest, self.receipts, SHA, RUN)

    def check(self, sha=SHA, run=RUN, trusted=None):
        return inspect(self.dir, sha, run, self.trusted if trusted is None else trusted)

    def test_valid(self):
        self.assertEqual(self.check()["authorization"], "DENY")

    def test_no_overwrite(self):
        with self.assertRaises(EvidenceRejected):
            prepare(self.dir, self.incident, self.manifest, self.receipts, SHA, RUN)

    def test_wrong_sha(self):
        with self.assertRaises(EvidenceRejected):
            self.check(sha="b" * 40)

    def test_wrong_run(self):
        with self.assertRaises(EvidenceRejected):
            self.check(run="2345679")

    def test_missing_incident(self):
        (self.dir / "incident.json").unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_missing_receipt(self):
        (self.dir / "custody-1.json").unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_unexpected_file(self):
        (self.dir / "ignored.json").write_text("malicious")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_tampered_manifest(self):
        path = self.dir / "archive.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_tampered_incident(self):
        path = self.dir / "incident.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_swapped_receipt(self):
        (self.dir / "custody-1.json").write_bytes((self.dir / "custody-0.json").read_bytes())
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_modified_index_digest(self):
        file = self.dir / "index.json"
        data = json.loads(file.read_text())
        data["files"][0]["sha256"] = "0" * 64
        file.write_bytes(serialize(data))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_modified_index_size(self):
        file = self.dir / "index.json"
        data = json.loads(file.read_text())
        data["files"][0]["size"] += 1
        file.write_bytes(serialize(data))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_wrong_custody_roster(self):
        other = dict(self.trusted)
        ident = next(iter(other))
        other[ident] = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(EvidenceRejected):
            self.check(trusted=other)

    def test_duplicate_json_field(self):
        path = self.dir / "index.json"
        path.write_bytes(path.read_bytes().replace(
            b'"authorization":"DENY"',
            b'"authorization":"DENY","authorization":"ALLOW"'))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_ci_smoke(self):
        self.assertTrue(exercise_ci(self.incident, SHA, RUN))


if __name__ == "__main__":
    unittest.main()
