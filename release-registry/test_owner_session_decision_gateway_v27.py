"""v27 owner-session gateway synthetic tests. No authentic identity provider."""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from recovery_operations_cockpit_v25 import OwnerReviewLedger
from owner_decision_cockpit_v26 import OwnerDecisionCockpit
from owner_session_decision_gateway_v27 import (
    GatewayError, OwnerSessionDecisionGateway,
)


class FakeSupervisor:
    def __init__(self):
        self.state = "READY"

    def inspect(self):
        return {
            "schema": "palaco-recovery-supervisor-inspection/v24",
            "target_sequence": 1, "pending": True,
            "attempts": 0, "max_attempts": 3,
            "state": self.state, "last_error": None,
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False,
        }


class GatewayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.supervisor = FakeSupervisor()
        self.ledger = OwnerReviewLedger(self.path / "review.sqlite")
        self.cockpit = OwnerDecisionCockpit(
            supervisor=self.supervisor, ledger=self.ledger)
        self.file = self.path / "gateway.sqlite"
        self.gateway = self.reopen()
        self.day = "2026-11-19"
        self.time = int(datetime(2026, 11, 19, 10, tzinfo=timezone.utc).timestamp())
        self.session = "synthetic-session"
        self.provider = lambda s, action, d: "owner-001" if (
            s == self.session and action == "OWNER_REVIEW" and d == self.day) else None

    def reopen(self):
        return OwnerSessionDecisionGateway(self.file, cockpit=self.cockpit)

    def begin(self, **kwargs):
        opts = dict(
            session_assertion=self.session, day=self.day, verdict="JA",
            evidence_ref="audit-001",
            expected_snapshot_sha256=self.cockpit.overview(
                day=self.day)["snapshot"]["snapshot_sha256"],
            verify_session=self.provider, trusted_now=lambda: self.time,
        )
        opts.update(kwargs)
        return self.gateway.begin(**opts)

    def confirm(self, challenge, **kwargs):
        opts = dict(
            challenge=challenge, session_assertion=self.session,
            verify_session=self.provider, trusted_now=lambda: self.time + 1,
            verify_owner=lambda *_: True,
            verify_trusted_date=lambda *_: True)
        opts.update(kwargs)
        return self.gateway.confirm(**opts)

    def test_begin_is_non_authorizing(self):
        output = self.begin()
        self.assertFalse(output["action_executed"])
        self.assertEqual(output["authorization"], "DENY")
        self.assertEqual(output["release"], "HOLD")
        self.assertIsNone(self.ledger.read(day=self.day))

    def test_confirm_ja_review_only(self):
        output = self.confirm(self.begin()["challenge"])
        self.assertEqual(output["verdict"], "JA")
        self.assertFalse(output["action_executed"])
        self.assertEqual(output["authorization"], "DENY")
        self.assertEqual(output["release"], "HOLD")

    def test_confirm_nee_review_only(self):
        output = self.confirm(self.begin(verdict="NEE")["challenge"])
        self.assertEqual(output["verdict"], "NEE")
        self.assertFalse(output["action_executed"])

    def test_replay_challenge_denied(self):
        challenge = self.begin()["challenge"]
        self.confirm(challenge)
        with self.assertRaisesRegex(GatewayError, "CHALLENGE_ALREADY_USED"):
            self.confirm(challenge)

    def test_two_challenges_same_day_denied_by_ledger(self):
        first = self.begin()["challenge"]
        second = self.begin(verdict="NEE")["challenge"]
        self.confirm(first)
        with self.assertRaises(Exception):
            self.confirm(second)
        self.assertEqual(self.ledger.read(day=self.day)["verdict"], "JA")

    def test_restart_preserves_challenge(self):
        challenge = self.begin()["challenge"]
        self.gateway = self.reopen()
        self.assertEqual(self.confirm(challenge)["verdict"], "JA")

    def test_restart_preserves_consumption(self):
        challenge = self.begin()["challenge"]
        self.confirm(challenge)
        self.gateway = self.reopen()
        with self.assertRaisesRegex(GatewayError, "CHALLENGE_ALREADY_USED"):
            self.confirm(challenge)

    def test_wrong_session_denied(self):
        challenge = self.begin()["challenge"]
        with self.assertRaisesRegex(GatewayError, "SESSION_NOT_AUTHORIZED"):
            self.confirm(challenge, session_assertion="different")

    def test_switched_owner_denied(self):
        challenge = self.begin()["challenge"]
        with self.assertRaisesRegex(GatewayError, "SESSION_IDENTITY_CHANGED"):
            self.confirm(challenge, verify_session=lambda *_: "owner-002")

    def test_owner_revoked_between_steps(self):
        challenge = self.begin()["challenge"]
        with self.assertRaisesRegex(GatewayError, "SESSION_NOT_AUTHORIZED"):
            self.confirm(challenge, verify_session=lambda *_: None)
        self.assertIsNone(self.ledger.read(day=self.day))

    def test_expired_challenge_denied(self):
        challenge = self.begin()["challenge"]
        with self.assertRaisesRegex(GatewayError, "CHALLENGE_EXPIRED"):
            self.confirm(challenge, trusted_now=lambda: self.time + 300)

    def test_clock_rollback_denied(self):
        challenge = self.begin()["challenge"]
        with self.assertRaisesRegex(GatewayError, "CHALLENGE_EXPIRED"):
            self.confirm(challenge, trusted_now=lambda: self.time - 1)

    def test_wrong_day_denied(self):
        with self.assertRaisesRegex(GatewayError, "TRUSTED_DATE_MISMATCH"):
            self.begin(trusted_now=lambda: self.time + 86400)

    def test_sunday_denied(self):
        with self.assertRaisesRegex(GatewayError, "SUNDAY_FREE"):
            self.begin(day="2026-11-22")

    def test_bad_expected_digest_denied(self):
        with self.assertRaisesRegex(GatewayError, "INVALID_EXPECTED_SNAPSHOT"):
            self.begin(expected_snapshot_sha256="invalid")

    def test_stale_digest_denied(self):
        with self.assertRaisesRegex(GatewayError, "STALE_SNAPSHOT"):
            self.begin(expected_snapshot_sha256="0"*64)

    def test_snapshot_change_denied_at_confirm(self):
        challenge = self.begin()["challenge"]
        self.supervisor.state = "BLOCKED"
        with self.assertRaises(Exception):
            self.confirm(challenge)
        self.assertIsNone(self.ledger.read(day=self.day))

    def test_denied_owner_policy(self):
        challenge = self.begin()["challenge"]
        with self.assertRaises(Exception):
            self.confirm(challenge, verify_owner=lambda *_: False)
        self.assertIsNone(self.ledger.read(day=self.day))

    def test_missing_external_date_policy(self):
        challenge = self.begin()["challenge"]
        with self.assertRaisesRegex(GatewayError, "EXTERNAL_TRUST_REQUIRED"):
            self.confirm(challenge, verify_trusted_date=None)

    def test_missing_session_provider(self):
        with self.assertRaisesRegex(GatewayError, "SESSION_PROVIDER_REQUIRED"):
            self.begin(verify_session=None)

    def test_session_exception_denied(self):
        def unavailable(*_):
            raise ConnectionError("synthetic")
        with self.assertRaisesRegex(GatewayError, "SESSION_UNAVAILABLE"):
            self.begin(verify_session=unavailable)

    def test_unknown_challenge_denied(self):
        with self.assertRaisesRegex(GatewayError, "UNKNOWN_CHALLENGE"):
            self.confirm("a"*43)

    def test_invalid_time_provider_denied(self):
        with self.assertRaisesRegex(GatewayError, "INVALID_TRUSTED_TIME"):
            self.begin(trusted_now=lambda: True)

    def test_challenge_digest_only_in_db(self):
        challenge = self.begin()["challenge"]
        with sqlite3.connect(self.file) as db:
            (digest,) = db.execute(
                "SELECT token_sha256 FROM owner_challenges").fetchone()
        self.assertNotEqual(challenge, digest)
        self.assertEqual(len(digest), 64)

    def test_challenge_mutation_guard(self):
        self.begin()
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE owner_challenges SET verdict='NEE'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM owner_challenges")

    def test_no_execution_methods(self):
        self.assertFalse(hasattr(self.gateway, "run_once"))
        self.assertFalse(hasattr(self.gateway, "restore"))
        self.assertFalse(hasattr(self.gateway, "authorize_release"))


if __name__ == "__main__":
    unittest.main()
