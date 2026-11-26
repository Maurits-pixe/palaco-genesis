"""v6.7 negative regressions: signed custody, manifest identity, run binding."""
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_verify_scm_ci_incident import valid_record
from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import public_id, serialize
from witness_anchor_v64 import write_once
from witness_custody_v67 import exercise_ci, sign, verify

SHA = "a" * 40
RUN = "123456789"


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.manifest = base / "archive.json"
        write_once(self.manifest, serialize({"decision": "HOLD", "authorization": "DENY"}))
        self.private = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.pinned = {public_id(k.public_key()): k.public_key() for k in self.private}
        self.receipts = [base / f"custody-{i}.json" for i in range(3)]
        for path, key in zip(self.receipts, self.private):
            write_once(path, sign(self.manifest.read_bytes(), SHA, RUN, key))

    def check(self, files=None, sha=SHA, run=RUN, trusted=None):
        verify(self.manifest, sha, run, self.pinned if trusted is None else trusted,
               self.receipts if files is None else files)

    def test_three_signatures(self):
        self.check()

    def test_two_signatures(self):
        self.check(self.receipts[:2])

    def test_one_signature_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check(self.receipts[:1])

    def test_missing_receipt_denied(self):
        self.receipts[2].unlink()
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_swapped_receipt_denied(self):
        self.receipts[1].write_bytes(self.receipts[0].read_bytes())
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_duplicate_path_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check([self.receipts[0], self.receipts[0]])

    def test_manifest_changed_denied(self):
        self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_sha_mismatch_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check(sha="b"*40)

    def test_run_mismatch_denied(self):
        with self.assertRaises(EvidenceRejected):
            self.check(run="123456790")

    def test_unknown_custodian_denied(self):
        outsider = Ed25519PrivateKey.generate()
        self.receipts[2].write_bytes(sign(self.manifest.read_bytes(), SHA, RUN, outsider))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_replaced_pinned_key_denied(self):
        wrong = dict(self.pinned)
        label = next(iter(wrong))
        wrong[label] = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(EvidenceRejected):
            self.check(trusted=wrong)

    def test_signature_changed_denied(self):
        record = json.loads(self.receipts[2].read_text())
        record["signature"] = "AA=="
        self.receipts[2].write_bytes(serialize(record))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_allow_claim_denied(self):
        record = json.loads(self.receipts[2].read_text())
        record["authorization"] = "ALLOW"
        self.receipts[2].write_bytes(serialize(record))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_duplicate_json_key_denied(self):
        original = self.receipts[0].read_text()
        self.receipts[0].write_text(original.replace(
            '"authorization":"DENY"', '"authorization":"DENY","authorization":"ALLOW"'))
        with self.assertRaises(EvidenceRejected):
            self.check()

    def test_ci_smoke(self):
        self.assertTrue(exercise_ci(json.dumps(valid_record()).encode(), SHA, RUN))


if __name__ == "__main__":
    unittest.main()
