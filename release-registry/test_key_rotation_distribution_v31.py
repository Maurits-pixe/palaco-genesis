"""PALACO v31 synthetic distribution / interrupted-rotation regressions.

All remote trust callbacks are synthetic fixtures, NOT production anchors.
"""
import base64
import sqlite3
import tempfile
from pathlib import Path
import unittest

from identity_key_rotation_v30 import GENESIS, IdentityKeyRotation
from identity_session_lifecycle_v29 import (
    GENESIS as LIFE_GENESIS, IdentityLifecycleRegistry)
from key_rotation_distribution_v31 import (
    DistributionError, KeyRotationDistribution, inspect_candidate)


class DistributionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.rotation = IdentityKeyRotation(root / "rotation.sqlite")
        self.lifecycle = IdentityLifecycleRegistry(root / "revocations.sqlite")
        self.distribution = KeyRotationDistribution(
            rotation=self.rotation, lifecycle=self.lifecycle)
        self.key = b"k" * 32
        self.next_key = b"n" * 32
        self.rotation_root = (0, GENESIS)
        self.lifecycle_root = (0, LIFE_GENESIS)
        self.enrolled = True

    def anchor_rotation(self):
        s = self.rotation.inspect_local()
        self.rotation_root = (s["sequence"], s["head"])

    def rotate(self):
        self.rotation.prepare(
            old_key="bootstrap", new_key="key-1", public_key=self.key,
            expected_sequence=0, expected_head=GENESIS,
            verify_predecessor=lambda seq, head: (seq, head) == self.rotation_root,
            check_policy=lambda *_: True)
        self.anchor_rotation()
        state = self.rotation.inspect_local()
        self.rotation.commit(
            old_key="bootstrap", new_key="key-1", public_key=self.key,
            expected_sequence=state["sequence"], expected_head=state["head"],
            verify_predecessor=lambda seq, head: (seq, head) == self.rotation_root,
            check_policy=lambda *_: True)
        self.anchor_rotation()

    def kwargs(self):
        return {
            "verify_rotation_head": lambda seq, head: (seq, head) == self.rotation_root,
            "verify_lifecycle_head": lambda seq, head: (seq, head) == self.lifecycle_root,
            "verify_active_key": lambda *_: self.enrolled,
        }

    def export(self, **extra):
        kwargs = self.kwargs()
        kwargs.update(extra)
        return self.distribution.candidate(
            key_id="key-1", public_key=self.key, **kwargs)

    def test_genesis_not_distributable(self):
        with self.assertRaisesRegex(DistributionError, "ROTATION_NOT_READY"):
            self.export()

    def test_committed_candidate(self):
        self.rotate()
        bundle = self.export()
        self.assertEqual(bundle["key_id"], "key-1")
        self.assertEqual(bundle["generation"], 1)
        self.assertEqual(bundle["release"], "HOLD")
        self.assertFalse(bundle["production_release_enabled"])

    def test_verified_candidate_diagnostic(self):
        self.rotate()
        self.assertIs(inspect_candidate(self.export(), **{
            "verify_rotation_head": self.kwargs()["verify_rotation_head"],
            "verify_lifecycle_head": self.kwargs()["verify_lifecycle_head"],
            "check_active_key": self.kwargs()["verify_active_key"],
        }), True)

    def test_pending_requires_manual_review(self):
        self.rotation.prepare(
            old_key="bootstrap", new_key="key-1", public_key=self.key,
            expected_sequence=0, expected_head=GENESIS,
            verify_predecessor=lambda *_: True,
            check_policy=lambda *_: True)
        self.anchor_rotation()
        report = self.distribution.recovery_inspection(
            verify_rotation_head=self.kwargs()["verify_rotation_head"])
        self.assertEqual(report["state"], "PENDING_EXTERNAL_REVIEW")
        self.assertTrue(report["manual_review_required"])
        with self.assertRaisesRegex(DistributionError, "ROTATION_NOT_READY"):
            self.export()

    def test_pending_unanchored_fails_recovery(self):
        self.rotation.prepare(
            old_key="bootstrap", new_key="key-1", public_key=self.key,
            expected_sequence=0, expected_head=GENESIS,
            verify_predecessor=lambda *_: True,
            check_policy=lambda *_: True)
        with self.assertRaisesRegex(DistributionError, "UNTRUSTED_ROTATION"):
            self.distribution.recovery_inspection(
                verify_rotation_head=self.kwargs()["verify_rotation_head"])

    def test_recovery_never_commits(self):
        self.rotate()
        before = self.rotation.inspect_local()
        report = self.distribution.recovery_inspection(
            verify_rotation_head=self.kwargs()["verify_rotation_head"])
        self.assertEqual(report["state"], "LOCALLY_COMMITTED")
        self.assertEqual(self.rotation.inspect_local(), before)

    def test_untrusted_rotation_root(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "UNTRUSTED_KEY"):
            self.export(verify_rotation_head=lambda *_: False)

    def test_non_boolean_rotation_root(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "UNTRUSTED_KEY"):
            self.export(verify_rotation_head=lambda *_: 1)

    def test_stale_lifecycle_root(self):
        self.rotate()
        self.lifecycle.revoke(
            "REVOKE_SESSION", "session-x",
            verify_publisher=lambda *_: True,
            verify_external_predecessor=lambda *_: True)
        with self.assertRaises(Exception):
            self.export()

    def test_revoked_signing_key(self):
        self.rotate()
        self.lifecycle.revoke(
            "REVOKE_SIGNING_KEY", "key-1",
            verify_publisher=lambda *_: True,
            verify_external_predecessor=lambda *_: True)
        self.lifecycle_root = self.lifecycle.current_local()
        with self.assertRaisesRegex(DistributionError, "UNTRUSTED_KEY"):
            self.export()

    def test_untrusted_enrollment(self):
        self.rotate()
        self.enrolled = False
        with self.assertRaisesRegex(DistributionError, "UNTRUSTED_KEY"):
            self.export()

    def test_nonboolean_enrollment(self):
        self.rotate()
        self.enrolled = 1
        with self.assertRaisesRegex(DistributionError, "UNTRUSTED_KEY"):
            self.export()

    def test_wrong_public_key(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "PUBLIC_KEY_MISMATCH"):
            self.distribution.candidate(
                key_id="key-1", public_key=self.next_key, **self.kwargs())

    def test_wrong_key_id(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "NOT_CURRENT_KEY"):
            self.distribution.candidate(
                key_id="bootstrap", public_key=self.key, **self.kwargs())

    def test_invalid_public_key(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "INVALID_PUBLIC_KEY"):
            self.distribution.candidate(
                key_id="key-1", public_key=b"short", **self.kwargs())

    def test_unavailable_remote_root(self):
        self.rotate()
        def offline(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(DistributionError, "TRUST_UNAVAILABLE"):
            self.export(verify_rotation_head=offline)

    def test_missing_remote_policy(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "EXTERNAL_TRUST_REQUIRED"):
            self.export(verify_active_key=None)

    def test_tampered_key_bundle_refused(self):
        self.rotate()
        bundle = self.export()
        bundle["public_key_b64"] = base64.b64encode(self.next_key).decode("ascii")
        self.assertFalse(inspect_candidate(bundle,
            verify_rotation_head=self.kwargs()["verify_rotation_head"],
            verify_lifecycle_head=self.kwargs()["verify_lifecycle_head"],
            check_active_key=self.kwargs()["verify_active_key"]))

    def test_tampered_release_refused(self):
        self.rotate()
        bundle = self.export()
        bundle["release"] = "GO"
        self.assertFalse(inspect_candidate(bundle,
            verify_rotation_head=self.kwargs()["verify_rotation_head"],
            verify_lifecycle_head=self.kwargs()["verify_lifecycle_head"],
            check_active_key=self.kwargs()["verify_active_key"]))

    def test_nonboolean_verifier_refused(self):
        self.rotate()
        self.assertFalse(inspect_candidate(
            self.export(), verify_rotation_head=lambda *_: 1,
            verify_lifecycle_head=self.kwargs()["verify_lifecycle_head"],
            check_active_key=self.kwargs()["verify_active_key"]))

    def test_missing_verifier_refused(self):
        self.rotate()
        self.assertFalse(inspect_candidate(
            self.export(), verify_rotation_head=None,
            verify_lifecycle_head=self.kwargs()["verify_lifecycle_head"],
            check_active_key=self.kwargs()["verify_active_key"]))

    def test_stale_distribution_after_rotation(self):
        self.rotate()
        bundle = self.export()
        state = self.rotation.inspect_local()
        self.rotation.prepare(
            old_key="key-1", new_key="key-2", public_key=self.next_key,
            expected_sequence=state["sequence"], expected_head=state["head"],
            verify_predecessor=self.kwargs()["verify_rotation_head"],
            check_policy=lambda *_: True)
        self.anchor_rotation()
        self.assertFalse(inspect_candidate(
            bundle, verify_rotation_head=self.kwargs()["verify_rotation_head"],
            verify_lifecycle_head=self.kwargs()["verify_lifecycle_head"],
            check_active_key=self.kwargs()["verify_active_key"]))

    def test_digest_deterministic(self):
        self.rotate()
        self.assertEqual(self.export(), self.export())

    def test_no_private_keys_in_bundle(self):
        self.rotate()
        bundle = self.export()
        self.assertNotIn("private_key", bundle)
        self.assertNotIn("secret", bundle)
        self.assertNotIn("token", bundle)

    def test_no_production_execution_api(self):
        for name in ("deploy", "sign", "issue", "authorize_release", "commit"):
            self.assertFalse(hasattr(self.distribution, name))

    def test_recovery_missing_anchor(self):
        self.rotate()
        with self.assertRaisesRegex(DistributionError, "EXTERNAL_ANCHOR_REQUIRED"):
            self.distribution.recovery_inspection(
                verify_rotation_head=None)

    def test_genesis_recovery_is_non_authorizing(self):
        report = self.distribution.recovery_inspection(
            verify_rotation_head=lambda *_: True)
        self.assertEqual(report["state"], "NO_GENERATION")
        self.assertEqual(report["authorization"], "DENY")

    def test_corrupted_rotation_refused(self):
        self.rotate()
        with sqlite3.connect(self.rotation.path) as db:
            db.execute("DROP TRIGGER rotation_no_update")
            db.execute("UPDATE key_rotation_events SET fingerprint=? "
                       "WHERE sequence=2", ("0"*64,))
        with self.assertRaises(Exception):
            self.export()


if __name__ == "__main__":
    unittest.main()
