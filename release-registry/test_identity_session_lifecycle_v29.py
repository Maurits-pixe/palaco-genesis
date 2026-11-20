"""Synthetic v29 lifecycle regression tests, NOT a real PALACO identity service."""
import base64
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from identity_session_lifecycle_v29 import (
    GENESIS, IdentityLifecycleRegistry, LifecycleError,
)
from owner_identity_integration_v28 import (
    OwnerIdentityAdapter, DOMAIN, SCHEMA,
)
from offline_stage import _canonical


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.file = Path(tmp.name) / "lifecycle.sqlite"
        self.registry = IdentityLifecycleRegistry(self.file)
        self.anchored = (0, GENESIS)
        self.publisher_allowed = True
        self.key_active = True
        self.owner_active = True
        self.now = int(datetime(2026, 11, 19, 10, tzinfo=timezone.utc).timestamp())
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.claims = {
            "schema": SCHEMA, "issuer": "palaco-one-test",
            "audience": "owner-cockpit-test", "subject": "owner-1",
            "session_id": "session-1", "device_id": "device-1",
            "issued_at": self.now - 20, "not_before": self.now - 20,
            "expires_at": self.now + 120, "mfa_at": self.now - 5,
            "auth_method": "phishing-resistant-mfa",
            "scope": "OWNER_REVIEW", "roles": ["OWNER"],
        }

    def token(self):
        signature = self.private.sign(DOMAIN + _canonical(self.claims))
        return _canonical({
            "claims": self.claims, "key_id": "key-1",
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }).decode("ascii")

    def anchor_callback(self, sequence, head):
        return (sequence, head) == self.anchored

    def revoke(self, kind, target, **overrides):
        kw = dict(verify_publisher=lambda *_: self.publisher_allowed,
                  verify_external_predecessor=self.anchor_callback)
        kw.update(overrides)
        result = self.registry.revoke(kind, target, **kw)
        return result

    def anchor_latest(self):
        # Test-only stand-in for independent monotonic anchor publication.
        self.anchored = self.registry.current_local()

    def verifier(self):
        trust_key, check_owner = self.registry.policy_callbacks(
            verify_external_head=self.anchor_callback,
            check_active_key=lambda *_: self.key_active,
            check_active_owner=lambda *_: self.owner_active)
        return OwnerIdentityAdapter(
            issuer="palaco-one-test", audience="owner-cockpit-test",
            pinned_public_keys={"key-1": self.public},
            trust_key=trust_key, check_current_owner=check_owner,
            trusted_now=lambda: self.now)

    def test_empty_trusted_genesis_allows_synthetic_session(self):
        self.assertEqual(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"),
                         "owner-1")

    def test_revoke_session(self):
        result = self.revoke("REVOKE_SESSION", "session-1")
        self.assertEqual(result["authorization"], "DENY")
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))
        self.anchor_latest()
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_revoke_device(self):
        self.revoke("REVOKE_DEVICE", "device-1")
        self.anchor_latest()
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_revoke_owner(self):
        self.revoke("REVOKE_OWNER", "owner-1")
        self.anchor_latest()
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_revoke_signing_key(self):
        self.revoke("REVOKE_SIGNING_KEY", "key-1")
        self.anchor_latest()
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_external_root_stale_fails_closed(self):
        self.revoke("REVOKE_SESSION", "session-1")
        with self.assertRaisesRegex(LifecycleError, "UNTRUSTED_LIFECYCLE"):
            self.registry.verified_snapshot(verify_external_head=self.anchor_callback)

    def test_external_attestation_unavailable_denies(self):
        def fail(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(LifecycleError, "EXTERNAL_ANCHOR_UNAVAILABLE"):
            self.registry.verified_snapshot(verify_external_head=fail)

    def test_missing_anchor_denies(self):
        with self.assertRaisesRegex(LifecycleError, "EXTERNAL_ANCHOR_REQUIRED"):
            self.registry.verified_snapshot(verify_external_head=None)

    def test_false_anchor_denies(self):
        with self.assertRaisesRegex(LifecycleError, "UNTRUSTED_LIFECYCLE"):
            self.registry.verified_snapshot(verify_external_head=lambda *_: False)

    def test_truthy_non_boolean_anchor_denies(self):
        with self.assertRaisesRegex(LifecycleError, "UNTRUSTED_LIFECYCLE"):
            self.registry.verified_snapshot(verify_external_head=lambda *_: 1)

    def test_revocation_requires_external_publisher(self):
        with self.assertRaisesRegex(LifecycleError, "EXTERNAL_TRUST_REQUIRED"):
            self.revoke("REVOKE_SESSION", "session-1", verify_publisher=None)

    def test_revocation_requires_anchor(self):
        with self.assertRaisesRegex(LifecycleError, "EXTERNAL_TRUST_REQUIRED"):
            self.revoke("REVOKE_SESSION", "session-1",
                        verify_external_predecessor=None)

    def test_denied_publisher_cannot_write(self):
        self.publisher_allowed = False
        with self.assertRaisesRegex(LifecycleError, "UNTRUSTED_REVOCATION"):
            self.revoke("REVOKE_SESSION", "session-1")
        self.assertEqual(self.registry.current_local(), (0, GENESIS))

    def test_revocation_with_stale_anchor_denies(self):
        self.revoke("REVOKE_SESSION", "session-1")
        with self.assertRaisesRegex(LifecycleError, "UNTRUSTED_REVOCATION"):
            self.revoke("REVOKE_OWNER", "owner-1")

    def test_event_sequence_restart(self):
        self.revoke("REVOKE_SESSION", "session-1")
        self.anchor_latest()
        self.revoke("REVOKE_DEVICE", "device-1")
        previous = self.registry.current_local()
        self.registry = IdentityLifecycleRegistry(self.file)
        self.assertEqual(self.registry.current_local(), previous)
        self.assertEqual(previous[0], 2)

    def test_duplicate_revocation_denied(self):
        self.revoke("REVOKE_SESSION", "session-1")
        self.anchor_latest()
        with self.assertRaisesRegex(LifecycleError, "ALREADY_REVOKED"):
            self.revoke("REVOKE_SESSION", "session-1")

    def test_bad_kind_denied(self):
        with self.assertRaisesRegex(LifecycleError, "INVALID_EVENT_KIND"):
            self.revoke("ISSUE_ADMIN", "owner-1")

    def test_bad_identifier_denied(self):
        with self.assertRaisesRegex(LifecycleError, "INVALID_IDENTIFIER"):
            self.revoke("REVOKE_SESSION", "../malformed")

    def test_external_owner_role_denied(self):
        self.owner_active = False
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_external_key_enrollment_denied(self):
        self.key_active = False
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_nonboolean_external_key_denied(self):
        self.key_active = 1
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_nonboolean_external_owner_denied(self):
        self.owner_active = 1
        self.assertIsNone(self.verifier()(self.token(), "OWNER_REVIEW", "2026-11-19"))

    def test_prohibit_update_delete(self):
        self.revoke("REVOKE_SESSION", "session-1")
        with sqlite3.connect(self.file) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE lifecycle_events SET target='other'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM lifecycle_events")

    def test_corruption_detected(self):
        self.revoke("REVOKE_SESSION", "session-1")
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER lifecycle_no_update")
            db.execute("UPDATE lifecycle_events SET target='other'")
        with self.assertRaisesRegex(LifecycleError, "CORRUPT_LIFECYCLE_CHAIN"):
            self.registry.current_local()

    def test_forged_genesis_roll_back_denied_by_anchor(self):
        self.revoke("REVOKE_SESSION", "session-1")
        self.anchor_latest()
        with sqlite3.connect(self.file) as db:
            db.execute("DROP TRIGGER lifecycle_no_delete")
            db.execute("DELETE FROM lifecycle_events")
        self.assertEqual(self.registry.current_local(), (0, GENESIS))
        with self.assertRaisesRegex(LifecycleError, "UNTRUSTED_LIFECYCLE"):
            self.registry.verified_snapshot(verify_external_head=self.anchor_callback)

    def test_only_revocation_no_grant(self):
        self.assertFalse(hasattr(self.registry, "grant_owner"))
        self.assertFalse(hasattr(self.registry, "issue_session"))
        self.assertFalse(hasattr(self.registry, "rotate_private_key"))


if __name__ == "__main__":
    unittest.main()
