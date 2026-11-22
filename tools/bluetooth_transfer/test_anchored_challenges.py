"""Synthetic anchor state + real Ed25519 review is tested elsewhere.

Anchor stub is a volatile fake and DOES NOT provide secure anti-rollback.
"""
from dataclasses import replace
from pathlib import Path
import hashlib
import sqlite3
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest

from anchored_challenges import (
    AnchoredChallengeLedger, EMPTY_ROOT, challenge_commitment,
)
from protocol import TransferError
from recovery_evidence import build_evidence
from recovery_inspection import RecoveryReport, RecoveryStatus
from signed_review_gate import (
    SignedReviewSubmission, ReviewDisposition, signing_message,
)


class FakeAnchor:
    def __init__(self):
        self.state = (0, EMPTY_ROOT)
        self.lock = threading.Lock()
        self.advance_then_fail = False
        self.offline = False

    def read(self):
        with self.lock:
            if self.offline:
                raise OSError("offline")
            return self.state

    def advance(self, previous, current):
        with self.lock:
            if self.state != previous:
                raise RuntimeError("compare-and-advance failed")
            if self.advance_then_fail:
                self.state = current
                raise OSError("uncertain checkpoint write")
            self.state = current


class FakeVerifier:
    """Not a production signature verifier."""

    def verify(self, key_id, message, signature):
        return signature == hashlib.sha256(message).digest()


class AnchoredChallengeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "challenges.sqlite"
        self.now = 150
        self.clock = lambda: self.now
        self.anchor = FakeAnchor()
        self.evidence = build_evidence(
            RecoveryReport(RecoveryStatus.UNAVAILABLE, None, None, None, None),
        )
        self.ledger = AnchoredChallengeLedger(self.path, self.clock, self.anchor)

    def request(self, token):
        signature = hashlib.sha256(
            signing_message(self.evidence, token),
        ).digest()
        return SignedReviewSubmission(
            self.evidence, "reviewer", token, signature,
        )

    def issue(self):
        return self.ledger.issue(self.evidence, "reviewer")

    def test_empty_ledger_checkpoint(self):
        self.assertEqual(self.anchor.state, (0, EMPTY_ROOT))

    def test_issue_updates_anchor(self):
        token = self.issue()
        self.assertEqual(len(token), 32)
        self.assertEqual(self.anchor.state[0], 1)
        self.assertNotEqual(self.anchor.state[1], EMPTY_ROOT)

    def test_restart_with_same_anchor(self):
        token = self.issue()
        again = AnchoredChallengeLedger.reopen(
            self.path, self.clock, self.anchor,
        )
        self.assertEqual(
            again.submit(self.request(token), FakeVerifier()),
            ReviewDisposition.HOLD_REVIEWABLE,
        )

    def test_consumption_changes_hash_not_count(self):
        token = self.issue()
        before = self.anchor.state
        self.ledger.submit(self.request(token), FakeVerifier())
        self.assertEqual(before[0], self.anchor.state[0])
        self.assertNotEqual(before[1], self.anchor.state[1])

    def test_replay_denied(self):
        token = self.issue()
        req = self.request(token)
        self.ledger.submit(req, FakeVerifier())
        with self.assertRaises(TransferError):
            self.ledger.submit(req, FakeVerifier())

    def test_reset_consumption_detected(self):
        token = self.issue()
        self.ledger.submit(self.request(token), FakeVerifier())
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE challenges SET consumed=0 WHERE token=?", (token,))
        with self.assertRaises(TransferError):
            AnchoredChallengeLedger.reopen(self.path, self.clock, self.anchor)

    def test_same_count_token_substitution_detected(self):
        token = self.issue()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE challenges SET token=? WHERE token=?", (b"x" * 32, token))
        with self.assertRaises(TransferError):
            AnchoredChallengeLedger.reopen(self.path, self.clock, self.anchor)

    def test_same_count_reviewer_change_detected(self):
        token = self.issue()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE challenges SET key_id='other' WHERE token=?", (token,))
        with self.assertRaises(TransferError):
            self.ledger.issue(self.evidence, "reviewer")

    def test_deleted_row_detected(self):
        token = self.issue()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM challenges WHERE token=?", (token,))
        with self.assertRaises(TransferError):
            self.ledger.submit(self.request(token), FakeVerifier())

    def test_untracked_row_detected(self):
        self.issue()
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO challenges VALUES (?,?,?,?,?,0)",
                (b"y"*32, self.evidence.sha256, "reviewer", 150, 400),
            )
        with self.assertRaises(TransferError):
            self.issue()

    def test_advance_uncertainty_holds_on_issuance(self):
        self.anchor.advance_then_fail = True
        with self.assertRaises(TransferError):
            self.issue()
        with self.assertRaises(TransferError):
            AnchoredChallengeLedger.reopen(self.path, self.clock, self.anchor)

    def test_advance_uncertainty_holds_on_consumption(self):
        token = self.issue()
        self.anchor.advance_then_fail = True
        with self.assertRaises(TransferError):
            self.ledger.submit(self.request(token), FakeVerifier())
        with self.assertRaises(TransferError):
            AnchoredChallengeLedger.reopen(self.path, self.clock, self.anchor)

    def test_anchor_unavailable_denied(self):
        self.anchor.offline = True
        with self.assertRaises(TransferError):
            self.issue()

    def test_expired_token_denied(self):
        token = self.issue()
        self.now += 301
        with self.assertRaises(TransferError):
            self.ledger.submit(self.request(token), FakeVerifier())

    def test_wrong_reviewer_denied(self):
        token = self.issue()
        req = replace(self.request(token), reviewer_key_id="other")
        with self.assertRaises(TransferError):
            self.ledger.submit(req, FakeVerifier())

    def test_concurrent_same_token_only_one(self):
        token = self.issue()
        other = AnchoredChallengeLedger.reopen(
            self.path, self.clock, self.anchor,
        )
        req = self.request(token)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(ledger.submit, req, FakeVerifier())
                for ledger in (self.ledger, other)
            ]
            result = []
            for f in futures:
                try:
                    result.append(f.result())
                except TransferError:
                    result.append(None)
        self.assertEqual(result.count(ReviewDisposition.HOLD_REVIEWABLE), 1)
        self.assertEqual(result.count(None), 1)

    def test_empty_rows_commitment(self):
        self.assertEqual(challenge_commitment([]), (0, EMPTY_ROOT))

    def test_malformed_row_denied(self):
        with self.assertRaises(TransferError):
            challenge_commitment([(b"bad", "a"*64, "reviewer", 1, 2, 0)])

    def test_new_constructor_rejects_existing_db(self):
        with self.assertRaises(TransferError):
            AnchoredChallengeLedger(self.path, self.clock, self.anchor)

    def test_missing_db_not_recreated(self):
        self.path.unlink()
        with self.assertRaises(TransferError):
            self.ledger.issue(self.evidence, "reviewer")


if __name__ == "__main__":
    unittest.main()
