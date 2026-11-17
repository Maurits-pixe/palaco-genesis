"""Synthetic v6 trust-boundary regression tests: fixtures grant no authority."""
from pathlib import Path
import hashlib
import tempfile
import unittest

from offline_journal import OfflineJournal
from offline_stage import GENESIS, make_candidate
from trusted_recovery import SCHEMA as CHECKPOINT_SCHEMA, prepare_backup
from trusted_evidence_v6 import (SCHEMA, EvidenceError, attestation_bytes,
                                 inspect_evidence)


class TrustedEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        journal = OfflineJournal(Path(temp.name) / "journal.sqlite")
        _, head, _ = journal.append(
            make_candidate("rio", "e1", 1, GENESIS, b"fixture"),
            expected_head=GENESIS)
        self.scope = "candidate-test"
        self.checkpoint = {
            "schema": CHECKPOINT_SCHEMA, "scope": self.scope,
            "sequence": 1, "head": head, "receipt": "fixture-only"
        }
        self.backup = prepare_backup(
            journal, self.checkpoint, scope=self.scope,
            verify=lambda statement, receipt: receipt == "fixture-only")
        self.attestation = {
            "schema": SCHEMA, "scope": self.scope, "key_id": "fixture-key",
            "signature": "fixture-attestation"
        }

    def accept_fixture(self, **overrides):
        params = {
            "scope": self.scope,
            "verify_checkpoint": lambda stmt, receipt: receipt == "fixture-only",
            "verify_attestation": lambda stmt, sig, kid:
                sig == "fixture-attestation" and kid == "fixture-key",
            "get_trusted_anchor": lambda scope:
                (self.checkpoint["sequence"], self.checkpoint["head"]),
        }
        params.update(overrides)
        return inspect_evidence(self.backup, self.checkpoint,
                                self.attestation, **params)

    def test_fixture_acceptance_never_authorizes(self):
        result = self.accept_fixture()
        self.assertEqual(result["authorization"], "DENY")
        self.assertEqual(result["release"], "HOLD")
        self.assertIs(result["production_release_enabled"], False)

    def test_missing_checkpoint_verifier(self):
        with self.assertRaises(EvidenceError):
            self.accept_fixture(verify_checkpoint=None)

    def test_missing_attestation_verifier(self):
        with self.assertRaises(EvidenceError):
            self.accept_fixture(verify_attestation=None)

    def test_missing_anchor(self):
        with self.assertRaises(EvidenceError):
            self.accept_fixture(get_trusted_anchor=None)

    def test_anchor_rollback(self):
        with self.assertRaisesRegex(EvidenceError, "ANCHOR_MISMATCH"):
            self.accept_fixture(get_trusted_anchor=lambda _: (0, GENESIS))

    def test_anchor_nonboolean_sequence(self):
        with self.assertRaisesRegex(EvidenceError, "ANCHOR_MISMATCH"):
            self.accept_fixture(get_trusted_anchor=lambda _: (True, self.checkpoint["head"]))

    def test_anchor_exception(self):
        def missing(_):
            raise OSError("offline")
        with self.assertRaisesRegex(EvidenceError, "ANCHOR_UNAVAILABLE"):
            self.accept_fixture(get_trusted_anchor=missing)

    def test_invalid_attestation(self):
        altered = dict(self.attestation, signature="")
        with self.assertRaises(EvidenceError):
            inspect_evidence(self.backup, self.checkpoint, altered,
                             scope=self.scope)

    def test_attestation_extra_authority_key(self):
        altered = dict(self.attestation, authorize=True)
        with self.assertRaises(EvidenceError):
            inspect_evidence(self.backup, self.checkpoint, altered,
                             scope=self.scope)

    def test_attestation_wrong_scope(self):
        altered = dict(self.attestation, scope="other")
        with self.assertRaisesRegex(EvidenceError, "SCOPE_MISMATCH"):
            inspect_evidence(self.backup, self.checkpoint, altered,
                             scope=self.scope)

    def test_false_signature_verification(self):
        with self.assertRaisesRegex(EvidenceError, "ATTESTATION_NOT_VERIFIED"):
            self.accept_fixture(verify_attestation=lambda *_: False)

    def test_truthy_signature_verification(self):
        with self.assertRaisesRegex(EvidenceError, "ATTESTATION_NOT_VERIFIED"):
            self.accept_fixture(verify_attestation=lambda *_: 1)

    def test_signature_verification_exception(self):
        def fail(*_):
            raise ConnectionError("no trustworthy keys")
        with self.assertRaises(EvidenceError):
            self.accept_fixture(verify_attestation=fail)

    def test_wrong_receipt(self):
        with self.assertRaisesRegex(EvidenceError, "BACKUP_NOT_VERIFIED"):
            self.accept_fixture(verify_checkpoint=lambda *_: False)

    def test_modified_backup(self):
        altered = bytearray(self.backup)
        altered[-1] ^= 1
        with self.assertRaises(EvidenceError):
            inspect_evidence(bytes(altered), self.checkpoint,
                             self.attestation, scope=self.scope,
                             verify_checkpoint=lambda *_: True,
                             verify_attestation=lambda *_: True,
                             get_trusted_anchor=lambda _: (
                                 self.checkpoint["sequence"], self.checkpoint["head"]))

    def test_statement_binds_exact_backup_digest(self):
        a = attestation_bytes(
            scope=self.scope, checkpoint=self.checkpoint,
            backup_sha256=hashlib.sha256(self.backup).hexdigest(),
            key_id="fixture-key")
        b = attestation_bytes(
            scope=self.scope, checkpoint=self.checkpoint,
            backup_sha256="0" * 64, key_id="fixture-key")
        self.assertNotEqual(a, b)

    def test_report_excludes_receipts_and_signatures(self):
        report = self.accept_fixture()
        rendered = str(report)
        self.assertNotIn("fixture-attestation", rendered)
        self.assertNotIn("fixture-only", rendered)


if __name__ == "__main__":
    unittest.main()
