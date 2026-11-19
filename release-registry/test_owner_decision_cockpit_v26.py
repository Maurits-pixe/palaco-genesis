"""PALACO v26 owner cockpit regression tests, with synthetic trust providers."""
from pathlib import Path
import tempfile
import unittest

from recovery_operations_cockpit_v25 import CockpitError, OwnerReviewLedger
from owner_decision_cockpit_v26 import (
    DecisionCockpitError, OwnerDecisionCockpit, render_owner_html,
)


class FakeSupervisor:
    def __init__(self):
        self.calls = 0
        self.state = "READY"

    def inspect(self):
        self.calls += 1
        return {
            "schema": "palaco-recovery-supervisor-inspection/v24",
            "target_sequence": 1, "pending": True,
            "attempts": 0, "max_attempts": 3,
            "state": self.state, "last_error": None,
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False,
        }


class OwnerDecisionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "reviews.sqlite"
        self.supervisor = FakeSupervisor()
        self.ledger = OwnerReviewLedger(self.path)
        self.cockpit = OwnerDecisionCockpit(
            supervisor=self.supervisor, ledger=self.ledger)
        self.day = "2026-11-19"

    def view(self, day=None):
        return self.cockpit.overview(day=self.day if day is None else day)

    def record(self, *, day=None, verdict="JA", **kwargs):
        day = self.day if day is None else day
        params = dict(
            day=day, verdict=verdict, owner_id="owner-fixture",
            evidence_ref="audit-ref-001",
            expected_snapshot_sha256=self.cockpit.overview(
                day=day)["snapshot"]["snapshot_sha256"],
            verify_owner=lambda *_: True,
            verify_trusted_date=lambda *_: True,
        )
        params.update(kwargs)
        return self.cockpit.record(**params)

    def test_ready_view(self):
        view = self.view()
        self.assertTrue(view["review_available"])
        self.assertEqual(view["review_reason"], "AWAITING_OWNER")
        self.assertIsNone(view["review"])
        self.assertEqual(view["authorization"], "DENY")
        self.assertFalse(view["operations_enabled"])

    def test_html_golden_green(self):
        html = render_owner_html(self.view())
        self.assertIn("#081f19", html)
        self.assertIn("#e4c57a", html)
        self.assertIn("PALACO", html)

    def test_html_no_execution(self):
        html = render_owner_html(self.view())
        self.assertNotIn("<form", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("onclick=", html)
        self.assertEqual(html.count(" disabled "), 2)

    def test_html_displays_snapshot_digest(self):
        view = self.view()
        self.assertIn(view["snapshot"]["snapshot_sha256"], render_owner_html(view))

    def test_ja_is_acknowledgment_only(self):
        result = self.record()
        self.assertEqual(result["verdict"], "JA")
        self.assertIs(result["action_executed"], False)
        self.assertEqual(result["authorization"], "DENY")
        self.assertEqual(result["release"], "HOLD")

    def test_nee_is_acknowledgment_only(self):
        result = self.record(verdict="NEE")
        self.assertEqual(result["verdict"], "NEE")
        self.assertFalse(result["action_executed"])

    def test_after_review_not_available(self):
        self.record()
        view = self.view()
        self.assertFalse(view["review_available"])
        self.assertEqual(view["review_reason"], "ALREADY_REVIEWED")
        self.assertEqual(view["review"]["verdict"], "JA")

    def test_sunday_free(self):
        view = self.view("2026-11-22")
        self.assertFalse(view["review_available"])
        self.assertEqual(view["review_reason"], "SUNDAY_FREE")

    def test_saturday_review(self):
        self.assertEqual(self.record(day="2026-11-21")["verdict"], "JA")

    def test_sunday_submission_denied(self):
        with self.assertRaisesRegex(DecisionCockpitError, "SUNDAY_FREE"):
            self.record(day="2026-11-22")

    def test_double_review_denied(self):
        self.record()
        with self.assertRaisesRegex(DecisionCockpitError, "ALREADY_REVIEWED"):
            self.record(verdict="NEE")

    def test_wrong_expected_snapshot_denied(self):
        with self.assertRaisesRegex(DecisionCockpitError, "STALE_SNAPSHOT"):
            self.record(expected_snapshot_sha256="0"*64)
        self.assertIsNone(self.ledger.read(day=self.day))

    def test_snapshot_changed_between_reads_denied(self):
        first = self.view()["snapshot"]["snapshot_sha256"]
        original = self.supervisor.inspect
        calls = [0]
        def switch():
            calls[0] += 1
            if calls[0] >= 2:
                self.supervisor.state = "BLOCKED"
            return original()
        self.supervisor.inspect = switch
        with self.assertRaisesRegex(DecisionCockpitError, "SNAPSHOT_CHANGED"):
            self.record(expected_snapshot_sha256=first)

    def test_source_unavailable_denied(self):
        def offline():
            raise ConnectionError("unavailable")
        self.supervisor.inspect = offline
        with self.assertRaises(CockpitError):
            self.view()

    def test_owner_denied(self):
        with self.assertRaisesRegex(CockpitError, "OWNER_NOT_VERIFIED"):
            self.record(verify_owner=lambda *_: False)

    def test_trusted_date_denied(self):
        with self.assertRaisesRegex(CockpitError, "UNTRUSTED_DATE"):
            self.record(verify_trusted_date=lambda *_: False)

    def test_missing_provider_denied(self):
        with self.assertRaisesRegex(CockpitError, "EXTERNAL_TRUST_REQUIRED"):
            self.record(verify_owner=None)

    def test_bad_verdict_denied(self):
        with self.assertRaisesRegex(CockpitError, "INVALID_VERDICT"):
            self.record(verdict="START")

    def test_bad_date_denied(self):
        with self.assertRaisesRegex(DecisionCockpitError, "INVALID_DATE"):
            self.view("2026-02-30")

    def test_boolean_day_denied(self):
        with self.assertRaisesRegex(DecisionCockpitError, "INVALID_DATE"):
            self.view(True)

    def test_html_tampered_authority_denied(self):
        view = self.view()
        view["release"] = "GO"
        with self.assertRaisesRegex(DecisionCockpitError, "UNSAFE_VIEW"):
            render_owner_html(view)

    def test_html_tampered_snapshot_denied(self):
        view = self.view()
        view["snapshot"]["status"] = "APPROVED"
        with self.assertRaises(CockpitError):
            render_owner_html(view)

    def test_html_inconsistent_review_state_denied(self):
        view = self.view()
        view["review_available"] = False
        with self.assertRaisesRegex(DecisionCockpitError, "INCONSISTENT_VIEW"):
            render_owner_html(view)

    def test_reopen_daily_review(self):
        result = self.record()
        reopened = OwnerDecisionCockpit(
            supervisor=self.supervisor, ledger=OwnerReviewLedger(self.path))
        actual = reopened.overview(day=self.day)
        self.assertEqual(actual["review"]["review_sha256"], result["review_sha256"])
        self.assertFalse(actual["review_available"])

    def test_no_recovery_execution_api(self):
        self.assertFalse(hasattr(self.cockpit, "run_once"))
        self.assertFalse(hasattr(self.cockpit, "reconcile"))
        self.assertFalse(hasattr(self.cockpit, "authorize_release"))


if __name__ == "__main__":
    unittest.main()
