"""WNRA-04O regression: simulated custody, never real attestation."""
from dataclasses import replace
import unittest

from windows_test_pin_custody_model import (
    CustodyDenied, DisposableCustody, PinRecord, authorization_from_test_result,
    DOMAIN,
)


A = "a" * 64
B = "b" * 64
COMMIT = "c" * 40


def pin(sequence=1, digest=A, predecessor=None, fixture="fixture-1"):
    return PinRecord(
        fixture_id=fixture,
        snapshot_digest=digest,
        source_commit=COMMIT,
        sequence=sequence,
        predecessor_digest=predecessor,
        evidence_ref="simulated-review-001",
    )


class DisposableCustodyTests(unittest.TestCase):
    def setUp(self):
        self.custody = DisposableCustody("fixture-1")

    def accept(self, record):
        self.custody.accept(record, simulated_reviewer_acceptance=True)

    def test_genesis_and_successor(self):
        self.accept(pin())
        self.accept(pin(2, B, A))
        self.assertEqual((1, 2), tuple(x.sequence for x in self.custody.history))
        self.assertTrue(self.custody.compare("fixture-1", B, simulated_custodian_available=True))

    def test_overwrite_or_sequence_rollback_denied(self):
        self.accept(pin())
        for attempt in (pin(1, B), pin(0, B), pin(3, B, A)):
            with self.subTest(attempt=attempt.sequence), self.assertRaises(CustodyDenied):
                self.accept(attempt)
        self.assertEqual((pin(),), self.custody.history)

    def test_predecessor_mismatch_atomic(self):
        self.accept(pin())
        with self.assertRaises(CustodyDenied):
            self.accept(pin(2, B, B))
        self.assertEqual((pin(),), self.custody.history)

    def test_cross_fixture_and_domain_replay_denied(self):
        for attempt in (pin(fixture="fixture-2"), replace(pin(), snapshot_domain="other-domain")):
            with self.subTest(attempt=attempt), self.assertRaises(CustodyDenied):
                self.accept(attempt)
        self.assertFalse(self.custody.history)

    def test_unreviewed_or_interrupted_replacement_preserves_prior(self):
        self.accept(pin())
        with self.assertRaises(CustodyDenied):
            self.custody.accept(pin(2, B, A), simulated_reviewer_acceptance=False)
        with self.assertRaises(CustodyDenied):
            self.accept(replace(pin(2, B, A), custody_status="PROPOSED"))
        self.assertEqual((pin(),), self.custody.history)

    def test_substitution_and_absent_custodian(self):
        self.accept(pin())
        self.assertFalse(self.custody.compare("fixture-1", B, simulated_custodian_available=True))
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-1", A, simulated_custodian_available=False)
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-2", A, simulated_custodian_available=True)

    def test_missing_pin_and_invalid_fields_denied(self):
        with self.assertRaises(CustodyDenied):
            self.custody.compare("fixture-1", A, simulated_custodian_available=True)
        for attempt in (replace(pin(), snapshot_digest="z" * 64),
                        replace(pin(), source_commit="not-a-commit"),
                        replace(pin(), sequence=True),
                        replace(pin(), evidence_ref=""),
                        replace(pin(), algorithm="sha1")):
            with self.subTest(attempt=attempt), self.assertRaises(CustodyDenied):
                self.accept(attempt)
        self.assertFalse(self.custody.history)

    def test_no_self_pin_independence_or_authorization_claim(self):
        self.accept(pin())
        # The caller can control both values in this simulation: equality is not attestation.
        self.assertTrue(self.custody.compare("fixture-1", A, simulated_custodian_available=True))
        self.assertEqual("DENY", authorization_from_test_result(True))
        self.assertEqual("DENY", authorization_from_test_result(False))


if __name__ == "__main__":
    unittest.main()
