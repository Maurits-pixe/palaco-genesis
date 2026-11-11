"""WNRA-04E negative lifecycle fixtures; no production lease credentials."""

import unittest

from windows_test_lease_model import (
    CONSUMED, DENIED, EXPIRED, REVOKED, LeaseDenied,
    TestLease, TestLeaseLedger,
)


class LeaseModelTests(unittest.TestCase):
    def setUp(self):
        self.ledger = TestLeaseLedger()
        self.ledger.issue(TestLease(
            lease_id="fixture-lease", statement_id="fixture-statement",
            consumer_id="reader-A", not_before=10, expires_at=20,
        ))

    def test_fresh_one_shot_redeem_and_handoff(self):
        first = self.ledger.redeem("fixture-lease", 0, 10, "reader-A")
        self.assertEqual(first.revision, 1)
        result = self.ledger.handoff("fixture-lease", 1, 11, "reader-A")
        self.assertEqual(result.state, CONSUMED)
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", 2, 12, "reader-A")

    def test_missing_invalid_and_duplicate_issue(self):
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("missing", 0, 10, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.issue(TestLease("fixture-lease", "other", "reader-A", 10, 20))
        with self.assertRaises(LeaseDenied):
            self.ledger.issue(TestLease("invalid", "statement", "reader", 20, 20))
        with self.assertRaises(LeaseDenied):
            self.ledger.issue(TestLease("boolean-time", "statement", "reader", True, 20))

    def test_expiry_boundary_and_early_redeem_deny(self):
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", 0, 9, "reader-A")
        self.assertEqual(self.ledger.inspect("fixture-lease").revision, 0)
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", 0, 20, "reader-A")
        self.assertEqual(self.ledger.inspect("fixture-lease").state, EXPIRED)

    def test_revoked_lease_and_revocation_before_handoff(self):
        active = self.ledger.redeem("fixture-lease", 0, 12, "reader-A")
        self.assertEqual(active.revision, 1)
        revoked = self.ledger.revoke("fixture-lease", 1, 13)
        self.assertEqual(revoked.state, REVOKED)
        with self.assertRaises(LeaseDenied):
            self.ledger.handoff("fixture-lease", 2, 14, "reader-A")

    def test_competing_redeemers_cannot_reuse_old_revision(self):
        snapshot_a = self.ledger.inspect("fixture-lease")
        snapshot_b = self.ledger.inspect("fixture-lease")
        self.ledger.redeem("fixture-lease", snapshot_a.revision, 12, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", snapshot_b.revision, 12, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", 1, 13, "reader-A")

    def test_consumer_binding_and_backwards_time_deny(self):
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", 0, 11, "reader-B")
        self.ledger.redeem("fixture-lease", 0, 15, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.handoff("fixture-lease", 1, 14, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.handoff("fixture-lease", 1, 16, "reader-B")

    def test_interrupted_redemption_is_terminal(self):
        self.ledger.redeem("fixture-lease", 0, 12, "reader-A")
        terminated = self.ledger.interrupt("fixture-lease", 1, 13)
        self.assertEqual(terminated.state, DENIED)
        with self.assertRaises(LeaseDenied):
            self.ledger.handoff("fixture-lease", 2, 14, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.redeem("fixture-lease", 2, 14, "reader-A")

    def test_expired_during_pending_handoff_denies(self):
        self.ledger.redeem("fixture-lease", 0, 19, "reader-A")
        with self.assertRaises(LeaseDenied):
            self.ledger.handoff("fixture-lease", 1, 20, "reader-A")
        self.assertEqual(self.ledger.inspect("fixture-lease").state, EXPIRED)


if __name__ == "__main__":
    unittest.main()
