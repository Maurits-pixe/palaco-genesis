"""Deterministic read-only recovery evidence regressions."""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from protocol import TransferError, chunks, make_offer
from receipt_integrity import ContentAnchoredReceiver, EMPTY_ROOT
from recovery_evidence import (
    DOMAIN, VERSION, RecoveryEvidence, build_evidence, inspect_evidence,
    verify_evidence,
)
from recovery_inspection import RecoveryReport, RecoveryStatus


class Anchor:
    def __init__(self):
        self.state = (0, EMPTY_ROOT)
        self.advances = 0

    def read(self):
        return self.state

    def advance(self, before, after):
        if self.state != before:
            raise TransferError("anchor mismatch")
        self.advances += 1
        self.state = after


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "records.sqlite"
        self.anchor = Anchor()
        self.offer = make_offer("citadel", "e" * 32, b"hello")

    def initialize(self):
        return ContentAnchoredReceiver(self.path, self.anchor)

    def receipt(self):
        self.initialize().accept(
            self.offer, chunks(b"hello"), user_approved=True,
            identity_verified=True,
        )

    def test_missing_database_generates_hold(self):
        evidence = inspect_evidence(self.path, self.anchor)
        self.assertTrue(verify_evidence(evidence))
        self.assertEqual(json.loads(evidence.canonical_json)["status"], "unavailable")
        self.assertFalse(self.path.exists())

    def test_empty_database_match_still_hold(self):
        self.initialize()
        doc = json.loads(inspect_evidence(self.path, self.anchor).canonical_json)
        self.assertEqual(doc["status"], "match")
        self.assertEqual(doc["decision"], "HOLD")

    def test_completed_receipt_still_hold(self):
        self.receipt()
        doc = json.loads(inspect_evidence(self.path, self.anchor).canonical_json)
        self.assertEqual(doc["database_count"], 1)
        self.assertEqual(doc["decision"], "HOLD")

    def test_stable_canonical_bytes(self):
        self.receipt()
        first = inspect_evidence(self.path, self.anchor)
        second = inspect_evidence(self.path, self.anchor)
        self.assertEqual(first, second)

    def test_fingerprint_is_domain_separated(self):
        self.initialize()
        evidence = inspect_evidence(self.path, self.anchor)
        import hashlib
        naive = hashlib.sha256(evidence.canonical_json.encode("ascii")).hexdigest()
        self.assertNotEqual(evidence.sha256, naive)
        self.assertTrue(DOMAIN)

    def test_detects_changed_report_status(self):
        self.initialize()
        evidence = inspect_evidence(self.path, self.anchor)
        tampered = evidence.canonical_json.replace('"status":"match"', '"status":"unavailable"')
        self.assertFalse(verify_evidence(RecoveryEvidence(tampered, evidence.sha256)))

    def test_detects_changed_digest(self):
        self.initialize()
        evidence = inspect_evidence(self.path, self.anchor)
        self.assertFalse(verify_evidence(replace(evidence, sha256="0" * 64)))

    def test_rejects_allow_decision(self):
        self.initialize()
        evidence = inspect_evidence(self.path, self.anchor)
        self.assertFalse(verify_evidence(RecoveryEvidence(
            evidence.canonical_json.replace('"decision":"HOLD"', '"decision":"ALLOW"'),
            evidence.sha256,
        )))

    def test_refuses_unknown_fields(self):
        self.initialize()
        evidence = inspect_evidence(self.path, self.anchor)
        doc = json.loads(evidence.canonical_json)
        doc["authorized"] = True
        self.assertFalse(verify_evidence(RecoveryEvidence(json.dumps(doc), evidence.sha256)))

    def test_rejects_inconsistent_status(self):
        bad = RecoveryReport(
            RecoveryStatus.MATCH, 1, 0, "a" * 64, "b" * 64,
        )
        with self.assertRaises(TransferError):
            build_evidence(bad)

    def test_unavailable_cannot_claim_root(self):
        bad = RecoveryReport(
            RecoveryStatus.UNAVAILABLE, None, None, "a" * 64, None,
        )
        with self.assertRaises(TransferError):
            build_evidence(bad)

    def test_database_ahead(self):
        self.initialize()
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO completed_transfers VALUES (?, ?)",
                       (self.offer.transfer_id, self.offer.payload_sha256))
        self.assertEqual(json.loads(inspect_evidence(self.path, self.anchor).canonical_json)["status"],
                         "database_ahead")

    def test_anchor_ahead(self):
        self.initialize()
        self.anchor.state = (1, "b" * 64)
        self.assertEqual(json.loads(inspect_evidence(self.path, self.anchor).canonical_json)["status"],
                         "anchor_ahead")

    def test_same_count_mutation_detected(self):
        self.receipt()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE completed_transfers SET transfer_id=?", ("a" * 32,))
        self.assertEqual(json.loads(inspect_evidence(self.path, self.anchor).canonical_json)["status"],
                         "content_mismatch")

    def test_no_anchor_advance_from_inspection(self):
        self.receipt()
        before = self.anchor.advances
        inspect_evidence(self.path, self.anchor)
        self.assertEqual(self.anchor.advances, before)

    def test_existing_receipt_database_not_modified(self):
        self.receipt()
        before = self.path.read_bytes()
        inspect_evidence(self.path, self.anchor)
        self.assertEqual(self.path.read_bytes(), before)

    def test_no_private_payload_leakage(self):
        self.receipt()
        doc = inspect_evidence(self.path, self.anchor).canonical_json
        self.assertNotIn("hello", doc)
        self.assertNotIn(str(self.path), doc)

    def test_protocol_version(self):
        self.initialize()
        self.assertEqual(json.loads(inspect_evidence(self.path, self.anchor).canonical_json)["protocol"],
                         VERSION)

    def test_invalid_report_type(self):
        with self.assertRaises(TransferError):
            build_evidence(None)

    def test_invalid_json_never_passes(self):
        self.assertFalse(verify_evidence(RecoveryEvidence("{", "0" * 64)))


if __name__ == "__main__":
    unittest.main()
