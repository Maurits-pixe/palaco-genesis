"""v13 governance SQLite regression tests: synthetic trust fixtures only."""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from durable_governance_audit_v13 import DurableGovernanceAudit, AuditJournalError
from recovery_governance_v12 import GENESIS, GovernanceError, proposal


class AuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name) / "governance.sqlite"
        self.journal = DurableGovernanceAudit(self.file)
        self.plan = proposal(
            b"synthetic-backup", destination_name="new-policy.sqlite",
            sequence=1, head="a" * 64,
            evidence_sha256=hashlib.sha256(b"fixture").hexdigest())
        self.journal.bind(self.plan)

    def owner(self, *, head=GENESIS, verdict="approve-candidate"):
        return self.journal.append(
            expected_head=head, actor_id="owner-fixture", role="owner",
            verdict=verdict, receipt="synthetic-receipt")

    def reviewer(self, head, *, verdict="approve-candidate"):
        return self.journal.append(
            expected_head=head, actor_id="reviewer-fixture",
            role="independent-reviewer", verdict=verdict,
            receipt="synthetic-reviewer-receipt")

    def test_empty_read_after_bind(self):
        plan, reviews, head = self.journal.read(expected_head=GENESIS)
        self.assertEqual(plan, self.plan)
        self.assertEqual(reviews, ())
        self.assertEqual(head, GENESIS)

    def test_restart_replays(self):
        event, head = self.owner()
        plan, reviews, replayed = DurableGovernanceAudit(self.file).read(
            expected_head=head)
        self.assertEqual((plan, reviews, replayed),
                         (self.plan, (event,), head))

    def test_two_reviews_after_restart(self):
        first, head = self.owner()
        second, new_head = DurableGovernanceAudit(self.file).append(
            expected_head=head, actor_id="reviewer-fixture",
            role="independent-reviewer", verdict="approve-candidate",
            receipt="synthetic-reviewer-receipt")
        _, reviews, restored = DurableGovernanceAudit(self.file).read(
            expected_head=new_head)
        self.assertEqual((reviews, restored), ((first, second), new_head))

    def test_no_second_bind(self):
        with self.assertRaisesRegex(AuditJournalError, "PROPOSAL_ALREADY_BOUND"):
            self.journal.bind(self.plan)

    def test_cannot_rebind_other_proposal(self):
        changed = dict(self.plan, proposal_sha256="0" * 64)
        with self.assertRaisesRegex(AuditJournalError, "PROPOSAL_ALREADY_BOUND"):
            self.journal.bind(changed)
        self.assertEqual(self.journal.read(expected_head=GENESIS)[0], self.plan)

    def test_stale_append_denied(self):
        _, head = self.owner()
        with self.assertRaisesRegex(AuditJournalError, "STALE_AUDIT_HEAD"):
            self.reviewer(GENESIS)
        self.assertEqual(len(self.journal.read(expected_head=head)[1]), 1)

    def test_duplicate_actor_denied(self):
        _, head = self.owner()
        with self.assertRaisesRegex(GovernanceError, "DUPLICATE_REVIEWER"):
            self.journal.append(
                expected_head=head, actor_id="owner-fixture",
                role="independent-reviewer", verdict="approve-candidate",
                receipt="fixture")
        self.assertEqual(len(self.journal.read(expected_head=head)[1]), 1)

    def test_invalid_role_denied_without_mutation(self):
        with self.assertRaisesRegex(GovernanceError, "INVALID_REVIEW_IDENTITY"):
            self.journal.append(
                expected_head=GENESIS, actor_id="x", role="admin",
                verdict="approve-candidate", receipt="fixture")
        self.assertEqual(len(self.journal.read(expected_head=GENESIS)[1]), 0)

    def test_stale_read_denied(self):
        self.owner()
        with self.assertRaisesRegex(AuditJournalError, "STALE_AUDIT_HEAD"):
            self.journal.read(expected_head=GENESIS)

    def test_review_update_trigger(self):
        self.owner()
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE audit_reviews SET body=? WHERE review_index=1",
                           (b"corrupted",))

    def test_review_delete_trigger(self):
        self.owner()
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM audit_reviews")

    def test_proposal_update_trigger(self):
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE audit_proposal SET body=? WHERE slot=1",
                           (b"corrupted",))

    def test_proposal_delete_trigger(self):
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM audit_proposal")

    def test_review_row_corruption(self):
        self.owner()
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER reviews_no_update")
            db.execute("UPDATE audit_reviews SET body=? WHERE review_index=1",
                       (b'{"forged":true}',))
        with self.assertRaises(AuditJournalError):
            self.journal.read(expected_head=GENESIS)

    def test_proposal_row_corruption(self):
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER proposal_no_update")
            db.execute("UPDATE audit_proposal SET body=? WHERE slot=1",
                       (b'{"forged":true}',))
        with self.assertRaises(AuditJournalError):
            self.journal.read(expected_head=GENESIS)

    def test_review_row_sequence_corruption(self):
        self.owner()
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER reviews_no_update")
            db.execute("UPDATE audit_reviews SET review_index=9 WHERE review_index=1")
        with self.assertRaises(AuditJournalError):
            self.journal.read(expected_head=GENESIS)

    def test_inspect_missing_trust_denied(self):
        self.owner()
        with self.assertRaisesRegex(GovernanceError, "EXTERNAL_TRUST_REQUIRED"):
            self.journal.inspect(
                verify_role=None, get_trusted_audit_anchor=None)

    def test_inspect_stale_anchor_denied(self):
        self.owner()
        with self.assertRaisesRegex(GovernanceError, "AUDIT_ANCHOR_MISMATCH"):
            self.journal.inspect(
                verify_role=lambda *_: True,
                get_trusted_audit_anchor=lambda _: (0, GENESIS))

    def test_inspect_fixture_never_authorizes(self):
        _, head = self.owner()
        _, head = self.reviewer(head)
        report = self.journal.inspect(
            verify_role=lambda *_: True,
            get_trusted_audit_anchor=lambda _: (2, head))
        self.assertIs(report["candidate_review_complete"], True)
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_inspect_reject_veto(self):
        _, head = self.owner()
        _, head = self.reviewer(head, verdict="reject")
        report = self.journal.inspect(
            verify_role=lambda *_: True,
            get_trusted_audit_anchor=lambda _: (2, head))
        self.assertIs(report["candidate_review_complete"], False)

    def test_empty_inspect_denied(self):
        with self.assertRaisesRegex(GovernanceError, "EXTERNAL_TRUST_REQUIRED"):
            self.journal.inspect(
                verify_role=lambda *_: True,
                get_trusted_audit_anchor=lambda _: (0, GENESIS))


if __name__ == "__main__":
    unittest.main()
