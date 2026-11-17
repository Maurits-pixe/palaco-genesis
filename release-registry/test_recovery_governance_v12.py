"""PALACO v12 candidate regression tests; callbacks are NOT real authority."""
import copy
import hashlib
import unittest

from recovery_governance_v12 import (
    GENESIS, GovernanceError, proposal, record_review,
    replay_reviews, inspect_governance,
)


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.plan = proposal(
            b"synthetic-backup", destination_name="new-policy.sqlite",
            sequence=1, head="a"*64,
            evidence_sha256=hashlib.sha256(b"synthetic-evidence").hexdigest())
        self.history = []
        self.head = GENESIS

    def add(self, actor="owner-1", role="owner", verdict="approve-candidate",
            receipt="fixture", **kwargs):
        event, head = record_review(
            self.history, plan=self.plan, expected_head=self.head,
            actor_id=actor, role=role, verdict=verdict, receipt=receipt, **kwargs)
        self.history.append(event)
        self.head = head
        return event

    def inspect(self, **kwargs):
        params = {"plan": self.plan,
                  "verify_role": lambda *_: True,
                  "get_trusted_audit_anchor": lambda _: (len(self.history), self.head)}
        params.update(kwargs)
        return inspect_governance(self.history, **params)

    def test_one_approval_not_complete(self):
        self.add()
        self.assertIs(self.inspect()["candidate_review_complete"], False)

    def test_two_independent_roles_complete(self):
        self.add()
        self.add(actor="reviewer-1", role="independent-reviewer")
        report = self.inspect()
        self.assertIs(report["candidate_review_complete"], True)
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_reject_veto(self):
        self.add()
        self.add(actor="reviewer-1", role="independent-reviewer",
                 verdict="reject")
        self.assertIs(self.inspect()["candidate_review_complete"], False)

    def test_duplicate_actor_denied(self):
        self.add()
        with self.assertRaisesRegex(GovernanceError, "DUPLICATE_REVIEWER"):
            self.add(actor="owner-1", role="independent-reviewer")

    def test_wrong_role_denied(self):
        with self.assertRaisesRegex(GovernanceError, "INVALID_REVIEW_IDENTITY"):
            self.add(role="administrator")

    def test_missing_receipt_denied(self):
        with self.assertRaisesRegex(GovernanceError, "INVALID_REVIEW_IDENTITY"):
            self.add(receipt="")

    def test_stale_head_denied(self):
        with self.assertRaisesRegex(GovernanceError, "STALE_REVIEW_HEAD"):
            record_review(self.history, plan=self.plan,
                expected_head="0"*64, actor_id="owner-1", role="owner",
                verdict="approve-candidate", receipt="fixture")

    def test_modified_event_denied(self):
        event = self.add()
        changed = dict(event, evidence_sha256="0"*64)
        with self.assertRaisesRegex(GovernanceError, "PROPOSAL_OR_EVIDENCE_MISMATCH"):
            replay_reviews([changed], plan=self.plan)

    def test_reordered_event_denied(self):
        self.add()
        self.add(actor="reviewer-1", role="independent-reviewer")
        with self.assertRaises(GovernanceError):
            replay_reviews(list(reversed(self.history)), plan=self.plan)

    def test_missing_external_verifier_denied(self):
        self.add()
        with self.assertRaisesRegex(GovernanceError, "EXTERNAL_TRUST_REQUIRED"):
            self.inspect(verify_role=None)

    def test_missing_external_anchor_denied(self):
        self.add()
        with self.assertRaisesRegex(GovernanceError, "EXTERNAL_TRUST_REQUIRED"):
            self.inspect(get_trusted_audit_anchor=None)

    def test_anchor_rollback_denied(self):
        self.add()
        with self.assertRaisesRegex(GovernanceError, "AUDIT_ANCHOR_MISMATCH"):
            self.inspect(get_trusted_audit_anchor=lambda _: (0, GENESIS))

    def test_nonboolean_role_denied(self):
        self.add()
        with self.assertRaisesRegex(GovernanceError, "ROLE_NOT_VERIFIED"):
            self.inspect(verify_role=lambda *_: 1)

    def test_role_exception_denied(self):
        self.add()
        def fail(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(GovernanceError, "TRUST_PROVIDER_UNAVAILABLE"):
            self.inspect(verify_role=fail)

    def test_empty_reviews_denied(self):
        with self.assertRaisesRegex(GovernanceError, "EXTERNAL_TRUST_REQUIRED"):
            self.inspect()

    def test_frozen_proposal_review(self):
        event = self.add()
        self.plan["evidence_sha256"] = "0"*64
        self.assertNotEqual(event["evidence_sha256"], self.plan["evidence_sha256"])

    def test_invalid_proposal_head(self):
        with self.assertRaisesRegex(GovernanceError, "INVALID_HEAD"):
            proposal(b"x", destination_name="new.sqlite", sequence=1,
                     head="bad", evidence_sha256="a"*64)

    def test_proposal_destination_binding(self):
        p2 = proposal(b"synthetic-backup", destination_name="other.sqlite",
                      sequence=1, head="a"*64,
                      evidence_sha256=hashlib.sha256(b"synthetic-evidence").hexdigest())
        self.assertNotEqual(p2["proposal_sha256"], self.plan["proposal_sha256"])

    def test_report_excludes_receipts(self):
        self.add(receipt="secret-fixture-receipt")
        self.assertNotIn("secret-fixture-receipt", str(self.inspect()))


if __name__ == "__main__":
    unittest.main()
