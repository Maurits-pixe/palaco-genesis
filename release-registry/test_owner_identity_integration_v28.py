"""v28 owner identity tests: synthetic signer and synthetic external policy."""
import base64
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from offline_stage import _canonical
from owner_identity_integration_v28 import (
    DOMAIN, SCHEMA, OwnerIdentityAdapter, OwnerIdentityError,
)
from owner_session_decision_gateway_v27 import OwnerSessionDecisionGateway, GatewayError
from owner_decision_cockpit_v26 import OwnerDecisionCockpit
from recovery_operations_cockpit_v25 import OwnerReviewLedger


class SyntheticSupervisor:
    def inspect(self):
        return {
            "schema": "palaco-recovery-supervisor-inspection/v24",
            "target_sequence": 1, "pending": True,
            "attempts": 0, "max_attempts": 3, "state": "READY",
            "last_error": None, "authorization": "DENY",
            "release": "HOLD", "production_release_enabled": False,
        }


class OwnerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.pinned = {"root-test": public}
        self.now = int(datetime(2026, 11, 19, 10, tzinfo=timezone.utc).timestamp())
        self.day = "2026-11-19"
        self.key_allowed = True
        self.owner_allowed = True
        self.adapter = self.make_adapter()
        self.claims = {
            "schema": SCHEMA, "issuer": "palaco-one-test",
            "audience": "owner-cockpit-test", "subject": "owner-001",
            "session_id": "session-001", "device_id": "device-001",
            "issued_at": self.now - 20, "not_before": self.now - 20,
            "expires_at": self.now + 120, "mfa_at": self.now - 10,
            "auth_method": "phishing-resistant-mfa",
            "scope": "OWNER_REVIEW", "roles": ["OWNER"],
        }

    def make_adapter(self, **overrides):
        opts = dict(
            issuer="palaco-one-test", audience="owner-cockpit-test",
            pinned_public_keys=self.pinned,
            trust_key=lambda *_: self.key_allowed,
            check_current_owner=lambda *_: self.owner_allowed,
            trusted_now=lambda: self.now,
        )
        opts.update(overrides)
        return OwnerIdentityAdapter(**opts)

    def token(self, claims=None, *, key_id="root-test", key=None, extras=None):
        data = self.claims if claims is None else claims
        signer = self.private if key is None else key
        signature = signer.sign(DOMAIN + _canonical(data))
        envelope = {"claims": data, "key_id": key_id,
                    "signature_b64": base64.b64encode(signature).decode("ascii")}
        if extras:
            envelope.update(extras)
        return _canonical(envelope).decode("ascii")

    def verify(self, token=None, *, adapter=None):
        return (self.adapter if adapter is None else adapter)(
            self.token() if token is None else token, "OWNER_REVIEW", self.day)

    def test_valid_synthetic_session(self):
        self.assertEqual(self.verify(), "owner-001")

    def test_invalid_signature_denied(self):
        wrong = Ed25519PrivateKey.generate()
        self.assertIsNone(self.verify(self.token(key=wrong)))

    def test_other_issuer_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, issuer="other"))))

    def test_other_audience_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, audience="other"))))

    def test_other_scope_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, scope="ADMIN"))))

    def test_missing_owner_role_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, roles=["USER"]))))

    def test_extra_role_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, roles=["OWNER", "ADMIN"]))))

    def test_missing_mfa_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, auth_method="password"))))

    def test_stale_mfa_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, mfa_at=self.now - 301))))

    def test_future_mfa_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, mfa_at=self.now + 1))))

    def test_expired_session_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, expires_at=self.now))))

    def test_future_not_before_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, not_before=self.now + 1))))

    def test_excessive_session_lifetime_denied(self):
        self.assertIsNone(self.verify(self.token(dict(self.claims, expires_at=self.now + 1000))))

    def test_revoked_key_denied(self):
        self.key_allowed = False
        self.assertIsNone(self.verify())

    def test_revoked_owner_denied(self):
        self.owner_allowed = False
        self.assertIsNone(self.verify())

    def test_nonboolean_key_policy_denied(self):
        self.key_allowed = 1
        self.assertIsNone(self.verify())

    def test_nonboolean_owner_policy_denied(self):
        self.owner_allowed = 1
        self.assertIsNone(self.verify())

    def test_unknown_key_denied(self):
        self.assertIsNone(self.verify(self.token(key_id="unknown")))

    def test_noncanonical_envelope_denied(self):
        self.assertIsNone(self.verify(self.token() + " "))

    def test_unsigned_extra_field_denied(self):
        self.assertIsNone(self.verify(self.token(extras={"owner": True})))

    def test_missing_claim_field_denied(self):
        claims = dict(self.claims)
        del claims["session_id"]
        self.assertIsNone(self.verify(self.token(claims)))

    def test_invalid_time_denied(self):
        self.assertIsNone(self.verify(adapter=self.make_adapter(trusted_now=lambda: True)))

    def test_unavailable_clock_denied(self):
        def offline():
            raise ConnectionError("clock unavailable")
        self.assertIsNone(self.verify(adapter=self.make_adapter(trusted_now=offline)))

    def test_unavailable_revocation_denied(self):
        def offline(*_):
            raise ConnectionError("revocation unavailable")
        self.assertIsNone(self.verify(adapter=self.make_adapter(
            check_current_owner=offline)))

    def test_untrusted_key_store_rejected(self):
        with self.assertRaisesRegex(OwnerIdentityError, "INVALID_PUBLIC_KEY"):
            self.make_adapter(pinned_public_keys={"root-test": b"wrong"})

    def test_missing_policy_rejected(self):
        with self.assertRaisesRegex(OwnerIdentityError, "EXTERNAL_TRUST_REQUIRED"):
            self.make_adapter(trust_key=None)

    def test_gateway_two_step_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            cockpit = OwnerDecisionCockpit(
                supervisor=SyntheticSupervisor(),
                ledger=OwnerReviewLedger(path / "reviews.sqlite"))
            gateway = OwnerSessionDecisionGateway(
                path / "gateway.sqlite", cockpit=cockpit)
            snapshot_sha = cockpit.overview(day=self.day)["snapshot"]["snapshot_sha256"]
            challenge = gateway.begin(
                session_assertion=self.token(), day=self.day, verdict="JA",
                evidence_ref="audit-test", expected_snapshot_sha256=snapshot_sha,
                verify_session=self.adapter, trusted_now=lambda: self.now)
            confirmation = gateway.confirm(
                challenge=challenge["challenge"], session_assertion=self.token(),
                verify_session=self.adapter, trusted_now=lambda: self.now + 1,
                verify_owner=lambda *_: True,
                verify_trusted_date=lambda *_: True)
            self.assertEqual(confirmation["authorization"], "DENY")
            self.assertFalse(confirmation["action_executed"])

    def test_gateway_revocation_between_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            cockpit = OwnerDecisionCockpit(
                supervisor=SyntheticSupervisor(),
                ledger=OwnerReviewLedger(path / "reviews.sqlite"))
            gateway = OwnerSessionDecisionGateway(
                path / "gateway.sqlite", cockpit=cockpit)
            snapshot_sha = cockpit.overview(day=self.day)["snapshot"]["snapshot_sha256"]
            issued = gateway.begin(
                session_assertion=self.token(), day=self.day, verdict="JA",
                evidence_ref="audit-test", expected_snapshot_sha256=snapshot_sha,
                verify_session=self.adapter, trusted_now=lambda: self.now)
            self.owner_allowed = False
            with self.assertRaisesRegex(GatewayError, "SESSION_NOT_AUTHORIZED"):
                gateway.confirm(
                    challenge=issued["challenge"], session_assertion=self.token(),
                    verify_session=self.adapter, trusted_now=lambda: self.now + 1,
                    verify_owner=lambda *_: True,
                    verify_trusted_date=lambda *_: True)
            self.assertIsNone(cockpit._ledger.read(day=self.day))


if __name__ == "__main__":
    unittest.main()
