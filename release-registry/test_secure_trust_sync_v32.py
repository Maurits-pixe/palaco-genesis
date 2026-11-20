"""Synthetic PALACO v32 trust synchronization tests; no live device trust."""
import base64
import hashlib
import sqlite3
import tempfile
from pathlib import Path
import unittest

from identity_key_rotation_v30 import GENESIS, IdentityKeyRotation
from identity_session_lifecycle_v29 import GENESIS as LIFE_GENESIS, IdentityLifecycleRegistry
from key_rotation_distribution_v31 import KeyRotationDistribution
from secure_trust_sync_v32 import SyncError, TrustSyncRegistry


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.rotation = IdentityKeyRotation(folder / "rotation.sqlite")
        self.lifecycle = IdentityLifecycleRegistry(folder / "lifecycle.sqlite")
        self.distribution = KeyRotationDistribution(
            rotation=self.rotation, lifecycle=self.lifecycle)
        self.sync = TrustSyncRegistry(folder / "sync.sqlite")
        self.rotation_root = (0, GENESIS)
        self.lifecycle_root = (0, LIFE_GENESIS)
        self.module_root = {"rio": (0, "GENESIS"), "citadel": (0, "GENESIS")}
        self.active = True
        self.device_ok = True
        self.public1 = b"a" * 32
        self.public2 = b"b" * 32
        self.rotate("bootstrap", "key-1", self.public1)
        self.bundle = self.get_bundle("key-1", self.public1)

    def rcheck(self, n, h):
        return (n, h) == self.rotation_root

    def lcheck(self, n, h):
        return (n, h) == self.lifecycle_root

    def mcheck(self, module, n, h):
        return (n, h) == self.module_root[module]

    def rotate(self, old, new, public):
        state = self.rotation.inspect_local()
        self.rotation.prepare(
            old_key=old, new_key=new, public_key=public,
            expected_sequence=state["sequence"], expected_head=state["head"],
            verify_predecessor=self.rcheck, check_policy=lambda *_: True)
        state = self.rotation.inspect_local()
        self.rotation_root = (state["sequence"], state["head"])
        self.rotation.commit(
            old_key=old, new_key=new, public_key=public,
            expected_sequence=state["sequence"], expected_head=state["head"],
            verify_predecessor=self.rcheck, check_policy=lambda *_: True)
        state = self.rotation.inspect_local()
        self.rotation_root = (state["sequence"], state["head"])

    def get_bundle(self, key, public):
        return self.distribution.candidate(
            key_id=key, public_key=public,
            verify_rotation_head=self.rcheck,
            verify_lifecycle_head=self.lcheck,
            verify_active_key=lambda *_: self.active)

    def trust(self):
        return dict(verify_sync_head=self.mcheck,
                    verify_rotation_head=self.rcheck,
                    verify_lifecycle_head=self.lcheck,
                    check_active_key=lambda *_: self.active)

    def stage(self, module="rio", bundle=None, **changes):
        kwargs = self.trust()
        kwargs.update(changes)
        return self.sync.stage(module, self.bundle if bundle is None else bundle,
                               **kwargs)

    def ack(self, challenge, module="rio", bundle=None, **changes):
        kwargs = self.trust()
        kwargs.update(changes)
        kwargs["verify_device"] = kwargs.pop(
            "verify_device", lambda *_: self.device_ok)
        return self.sync.acknowledge(
            module, self.bundle if bundle is None else bundle,
            challenge, "synthetic-device-proof", **kwargs)

    def anchor(self, module="rio"):
        info = self.sync.inspect_local(module)
        self.module_root[module] = (info["generation"], info["receipt_hash"])

    def test_first_staging_is_non_authorizing(self):
        out = self.stage()
        self.assertEqual(out["generation"], 1)
        self.assertEqual(out["authorization"], "DENY")
        self.assertEqual(self.sync.inspect_local("rio")["generation"], 0)

    def test_ack_is_diagnostic_not_installation(self):
        result = self.ack(self.stage()["challenge"])
        self.assertTrue(result["device_acknowledged"])
        self.assertFalse(result["key_installed"])
        self.assertEqual(result["release"], "HOLD")

    def test_one_time_challenge(self):
        token = self.stage()["challenge"]
        self.ack(token)
        with self.assertRaisesRegex(SyncError, "REPLAYED_CHALLENGE"):
            self.ack(token)

    def test_unknown_challenge_rejected(self):
        with self.assertRaisesRegex(SyncError, "UNKNOWN_CHALLENGE"):
            self.ack("a"*43)

    def test_invalid_challenge_rejected(self):
        with self.assertRaisesRegex(SyncError, "INVALID_CHALLENGE"):
            self.ack("bad")

    def test_wrong_module_refused(self):
        token = self.stage()["challenge"]
        with self.assertRaisesRegex(SyncError, "CHALLENGE_BINDING_MISMATCH"):
            self.ack(token, module="citadel")

    def test_duplicate_generation_denied(self):
        self.ack(self.stage()["challenge"])
        self.anchor()
        with self.assertRaisesRegex(SyncError, "DOWNGRADE_OR_GENERATION_GAP"):
            self.stage()

    def test_unanchored_module_cannot_stage_next(self):
        self.ack(self.stage()["challenge"])
        self.rotate("key-1", "key-2", self.public2)
        second = self.get_bundle("key-2", self.public2)
        with self.assertRaisesRegex(SyncError, "UNTRUSTED_BUNDLE"):
            self.stage(bundle=second)

    def test_sequential_generation(self):
        self.ack(self.stage()["challenge"])
        self.anchor()
        self.rotate("key-1", "key-2", self.public2)
        second = self.get_bundle("key-2", self.public2)
        out = self.stage(bundle=second)
        self.assertEqual(self.ack(out["challenge"], bundle=second)["generation"], 2)

    def test_generation_gap_refused(self):
        bundle = dict(self.bundle, generation=3)
        with self.assertRaisesRegex(SyncError, "DOWNGRADE_OR_GENERATION_GAP"):
            self.stage(bundle=bundle)

    def test_revoked_key_refused(self):
        self.lifecycle.revoke(
            "REVOKE_SIGNING_KEY", "key-1",
            verify_publisher=lambda *_: True,
            verify_external_predecessor=lambda *_: True)
        self.lifecycle_root = self.lifecycle.current_local()
        with self.assertRaisesRegex(SyncError, "UNTRUSTED_BUNDLE"):
            self.stage()

    def test_untrusted_rotation_refused(self):
        with self.assertRaisesRegex(SyncError, "UNTRUSTED_BUNDLE"):
            self.stage(verify_rotation_head=lambda *_: False)

    def test_false_device_proof_denied(self):
        token = self.stage()["challenge"]
        self.device_ok = False
        with self.assertRaisesRegex(SyncError, "UNVERIFIED_ACKNOWLEDGMENT"):
            self.ack(token)
        self.assertEqual(self.sync.inspect_local("rio")["generation"], 0)

    def test_nonboolean_device_denied(self):
        token = self.stage()["challenge"]
        self.device_ok = 1
        with self.assertRaisesRegex(SyncError, "UNVERIFIED_ACKNOWLEDGMENT"):
            self.ack(token)

    def test_missing_device_verifier_denied(self):
        token = self.stage()["challenge"]
        with self.assertRaisesRegex(SyncError, "EXTERNAL_TRUST_REQUIRED"):
            self.ack(token, verify_device=None)

    def test_missing_root_denied(self):
        with self.assertRaisesRegex(SyncError, "EXTERNAL_TRUST_REQUIRED"):
            self.stage(verify_sync_head=None)

    def test_stale_root_denied(self):
        with self.assertRaisesRegex(SyncError, "UNTRUSTED_BUNDLE"):
            self.stage(verify_sync_head=lambda *_: False)

    def test_bundle_replaced_after_stage_denied(self):
        token = self.stage()["challenge"]
        changed = dict(self.bundle, bundle_sha256="0"*64)
        with self.assertRaisesRegex(SyncError, "CHALLENGE_BINDING_MISMATCH"):
            self.ack(token, bundle=changed)

    def test_current_bundle_changed_after_stage_denied(self):
        token = self.stage()["challenge"]
        self.rotate("key-1", "key-2", self.public2)
        with self.assertRaisesRegex(SyncError, "UNVERIFIED_ACKNOWLEDGMENT"):
            self.ack(token)

    def test_two_modules_independent(self):
        first = self.stage("rio")
        second = self.stage("citadel")
        self.ack(first["challenge"])
        self.ack(second["challenge"], module="citadel")
        self.assertEqual(self.sync.inspect_local("rio")["generation"], 1)
        self.assertEqual(self.sync.inspect_local("citadel")["generation"], 1)

    def test_restart_preserves_receipt(self):
        self.ack(self.stage()["challenge"])
        self.sync = TrustSyncRegistry(self.sync.path)
        self.assertEqual(self.sync.inspect_local("rio")["generation"], 1)

    def test_corruption_detected(self):
        self.ack(self.stage()["challenge"])
        with sqlite3.connect(self.sync.path) as db:
            db.execute("DROP TRIGGER sync_receipts_no_update")
            db.execute("UPDATE sync_receipts SET receipt_hash=?", ("0"*64,))
        with self.assertRaisesRegex(SyncError, "CORRUPT_RECEIPT_CHAIN"):
            self.sync.inspect_local("rio")

    def test_ordinary_update_delete_blocked(self):
        self.ack(self.stage()["challenge"])
        with sqlite3.connect(self.sync.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE sync_receipts SET bundle_hash=?", ("0"*64,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM sync_receipts")

    def test_challenge_secret_not_stored(self):
        token = self.stage()["challenge"]
        with sqlite3.connect(self.sync.path) as db:
            (stored,) = db.execute("SELECT token_hash FROM sync_challenges").fetchone()
        self.assertEqual(stored, hashlib.sha256(token.encode("ascii")).hexdigest())
        self.assertNotEqual(stored, token)

    def test_unavailable_device_denied(self):
        token = self.stage()["challenge"]
        def offline(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(SyncError, "TRUST_UNAVAILABLE"):
            self.ack(token, verify_device=offline)

    def test_unavailable_rotation_denied(self):
        def offline(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(SyncError, "UNTRUSTED_BUNDLE"):
            self.stage(verify_rotation_head=offline)

    def test_nonboolean_sync_anchor_denied(self):
        with self.assertRaisesRegex(SyncError, "UNTRUSTED_BUNDLE"):
            self.stage(verify_sync_head=lambda *_: 1)

    def test_no_execution_api(self):
        for name in ("install", "deploy", "issue_private_key", "authorize_release"):
            self.assertFalse(hasattr(self.sync, name))


if __name__ == "__main__":
    unittest.main()
