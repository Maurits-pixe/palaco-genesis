"""Negative-path regression tests for independent PALACO SCM incident verifier."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_scm_ci_incident import (
    CANONICAL,
    EvidenceRejected,
    verify_bytes,
    verify_once,
)


def valid_record():
    return {
        "protocol": "PALACO-BT-CI-INCIDENT-V1",
        "incident": "WORKER_FAULTED",
        "decision": "HOLD",
        "authorization": "DENY",
        "canonical_sha256": hashlib.sha256(CANONICAL).hexdigest(),
        "independent_signature": False,
        "native_security_verified": False,
    }


class IndependentIncidentVerifierTests(unittest.TestCase):
    def test_valid_and_replay_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            evidence = Path(folder) / "incident.json"
            receipt = Path(folder) / "receipt.txt"
            evidence.write_text(json.dumps(valid_record()), encoding="utf-8")
            verify_once(evidence, receipt)
            self.assertIn("HOLD|DENY", receipt.read_text(encoding="ascii"))
            with self.assertRaises(EvidenceRejected):
                verify_once(evidence, receipt)

    def test_missing_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(EvidenceRejected):
                verify_once(Path(folder) / "missing.json", Path(folder) / "receipt")

    def test_missing_field_rejected(self):
        record = valid_record()
        del record["authorization"]
        with self.assertRaises(EvidenceRejected):
            verify_bytes(json.dumps(record).encode())

    def test_tampered_status_rejected(self):
        record = valid_record()
        record["authorization"] = "ALLOW"
        with self.assertRaises(EvidenceRejected):
            verify_bytes(json.dumps(record).encode())

    def test_recomputed_checksum_is_not_source_authentication(self):
        record = valid_record()
        record["incident"] = "IMPERSONATED"
        record["canonical_sha256"] = hashlib.sha256(
            b"PALACO-BT-CI-INCIDENT-V1|IMPERSONATED|HOLD|DENY"
        ).hexdigest()
        with self.assertRaises(EvidenceRejected):
            verify_bytes(json.dumps(record).encode())

    def test_duplicate_json_field_rejected(self):
        raw = json.dumps(valid_record())
        raw = raw.replace('"authorization": "DENY"',
                          '"authorization": "DENY", "authorization": "ALLOW"')
        with self.assertRaises(EvidenceRejected):
            verify_bytes(raw.encode())

    def test_extra_field_rejected(self):
        record = valid_record()
        record["pretend_signature"] = "trusted"
        with self.assertRaises(EvidenceRejected):
            verify_bytes(json.dumps(record).encode())

    def test_invalid_flags_rejected(self):
        for flag in ("independent_signature", "native_security_verified"):
            with self.subTest(flag=flag):
                record = valid_record()
                record[flag] = True
                with self.assertRaises(EvidenceRejected):
                    verify_bytes(json.dumps(record).encode())

    def test_non_boolean_flag_rejected(self):
        record = valid_record()
        record["independent_signature"] = 0
        with self.assertRaises(EvidenceRejected):
            verify_bytes(json.dumps(record).encode())

    def test_garbage_or_oversized_rejected(self):
        for raw in (b"", b"not json", b"{" + b"x" * 4096 + b"}", b"\xff"):
            with self.subTest(size=len(raw)):
                with self.assertRaises(EvidenceRejected):
                    verify_bytes(raw)

    def test_existing_receipt_blocks_new_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            evidence = Path(folder) / "incident.json"
            receipt = Path(folder) / "receipt.txt"
            evidence.write_text(json.dumps(valid_record()), encoding="utf-8")
            receipt.write_text("occupied", encoding="ascii")
            with self.assertRaises(EvidenceRejected):
                verify_once(evidence, receipt)
            self.assertEqual(receipt.read_text(encoding="ascii"), "occupied")


if __name__ == "__main__":
    unittest.main()
