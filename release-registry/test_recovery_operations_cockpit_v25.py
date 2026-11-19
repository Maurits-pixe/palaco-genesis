"""Synthetic PALACO v25 cockpit regression tests: no operational authority."""
from datetime import date
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from recovery_operations_cockpit_v25 import (
    CockpitError, OwnerReviewLedger, snapshot, render_html,
)


class FakeSupervisor:
    def __init__(self, **changes):
        self.report = {
            "schema": "palaco-recovery-supervisor-inspection/v24",
            "target_sequence": 1, "pending": True,
            "attempts": 1, "max_attempts": 3, "state": "RETRYABLE",
            "last_error": "EXTERNAL_ANCHOR_UNAVAILABLE",
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False,
        }
        self.report.update(changes)
        self.calls = 0

    def inspect(self):
        self.calls += 1
        return dict(self.report)


class CockpitTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "owner-ledger.sqlite"
        self.ledger = OwnerReviewLedger(self.path)
        self.supervisor = FakeSupervisor()
        self.snap = snapshot(self.supervisor)
        # 2026-11-19 is Thursday; test date is otherwise synthetic.
        self.day = "2026-11-19"

    def record(self, **overrides):
        kwargs = {
            "day": self.day, "verdict": "JA", "owner_id": "owner-fixture",
            "evidence_ref": "audit-001",
            "verify_owner": lambda *_: True,
            "verify_trusted_date": lambda *_: True,
        }
        kwargs.update(overrides)
        return self.ledger.record(self.snap, **kwargs)

    def test_snapshot_read_only(self):
        result = snapshot(self.supervisor)
        self.assertEqual(result["status"], "RETRYABLE")
        self.assertFalse(result["operations_enabled"])
        self.assertEqual(result["authorization"], "DENY")
        self.assertEqual(result["release"], "HOLD")

    def test_snapshot_is_deterministic(self):
        self.assertEqual(snapshot(self.supervisor), self.snap)

    def test_html_has_no_buttons_forms_or_scripts(self):
        html = render_html(self.snap)
        for forbidden in ("<form", "<button", "<script", "onclick="):
            self.assertNotIn(forbidden, html.lower())
        self.assertIn("GO-13 HOLD", html)

    def test_html_includes_status(self):
        html = render_html(self.snap)
        self.assertIn("RETRYABLE", html)
        self.assertIn("EXTERNAL_ANCHOR_UNAVAILABLE", html)

    def test_tampered_snapshot_denied(self):
        altered = dict(self.snap, authorization="ALLOW")
        with self.assertRaisesRegex(CockpitError, "UNSAFE_SNAPSHOT"):
            render_html(altered)

    def test_tampered_digest_denied(self):
        altered = dict(self.snap, snapshot_sha256="0"*64)
        with self.assertRaisesRegex(CockpitError, "UNSAFE_SNAPSHOT"):
            render_html(altered)

    def test_untrusted_supervisor_denied(self):
        with self.assertRaisesRegex(CockpitError, "UNSAFE_SOURCE_REPORT"):
            snapshot(FakeSupervisor(authorization="ALLOW"))

    def test_inconsistent_pending_denied(self):
        with self.assertRaisesRegex(CockpitError, "INCONSISTENT_SOURCE"):
            snapshot(FakeSupervisor(pending=False, target_sequence=1))

    def test_unknown_report_field_denied(self):
        supervisor = FakeSupervisor()
        supervisor.report["execute_restore"] = True
        with self.assertRaisesRegex(CockpitError, "INVALID_SOURCE_REPORT"):
            snapshot(supervisor)

    def test_ja_review_only_records(self):
        result = self.record()
        self.assertEqual(result["verdict"], "JA")
        self.assertIs(result["action_executed"], False)
        self.assertEqual(result["authorization"], "DENY")
        self.assertEqual(result["release"], "HOLD")

    def test_nee_review_only_records(self):
        result = self.record(verdict="NEE")
        self.assertEqual(result["verdict"], "NEE")
        self.assertFalse(result["action_executed"])

    def test_single_review_per_date(self):
        self.record()
        with self.assertRaisesRegex(CockpitError, "ALREADY_REVIEWED_FOR_DAY"):
            self.record(verdict="NEE")

    def test_reopened_ledger_reads_same_record(self):
        result = self.record()
        recovered = OwnerReviewLedger(self.path).read(day=self.day)
        self.assertEqual(recovered["review_sha256"], result["review_sha256"])
        self.assertFalse(recovered["action_executed"])

    def test_sunday_disallowed(self):
        with self.assertRaisesRegex(CockpitError, "NON_WORKDAY_OR_INVALID_DATE"):
            self.record(day="2026-11-22")

    def test_saturday_allowed(self):
        self.assertEqual(self.record(day="2026-11-21")["verdict"], "JA")

    def test_missing_owner_provider_denied(self):
        with self.assertRaisesRegex(CockpitError, "EXTERNAL_TRUST_REQUIRED"):
            self.record(verify_owner=None)

    def test_missing_trusted_date_provider_denied(self):
        with self.assertRaisesRegex(CockpitError, "EXTERNAL_TRUST_REQUIRED"):
            self.record(verify_trusted_date=None)

    def test_rejected_owner_denied(self):
        with self.assertRaisesRegex(CockpitError, "OWNER_NOT_VERIFIED"):
            self.record(verify_owner=lambda *_: False)
        self.assertIsNone(self.ledger.read(day=self.day))

    def test_non_boolean_owner_denied(self):
        with self.assertRaisesRegex(CockpitError, "OWNER_NOT_VERIFIED"):
            self.record(verify_owner=lambda *_: 1)

    def test_trusted_date_false_denied(self):
        with self.assertRaisesRegex(CockpitError, "UNTRUSTED_DATE"):
            self.record(verify_trusted_date=lambda *_: False)

    def test_owner_provider_exception_denied(self):
        def offline(*_):
            raise ConnectionError("private identity provider unavailable")
        with self.assertRaisesRegex(CockpitError, "TRUST_PROVIDER_UNAVAILABLE"):
            self.record(verify_owner=offline)

    def test_untrusted_verdict_denied(self):
        with self.assertRaisesRegex(CockpitError, "INVALID_VERDICT"):
            self.record(verdict="GO")

    def test_append_only_guards(self):
        self.record()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE cockpit_owner_reviews SET verdict='NEE'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM cockpit_owner_reviews")

    def test_modified_review_detected(self):
        self.record()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER owner_reviews_no_update")
            db.execute("UPDATE cockpit_owner_reviews SET verdict='NEE'")
        with self.assertRaisesRegex(CockpitError, "CORRUPT_OWNER_REVIEW"):
            self.ledger.read(day=self.day)

    def test_no_execution_callbacks_exist(self):
        self.assertFalse(hasattr(self.ledger, "run_once"))
        self.assertFalse(hasattr(self.ledger, "reconcile"))
        self.assertFalse(hasattr(self.ledger, "restore"))


if __name__ == "__main__":
    unittest.main()
