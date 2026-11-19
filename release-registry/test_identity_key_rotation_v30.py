"""PALACO v30 synthetic key rotation tests: NO real key issuance or trust."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from identity_key_rotation_v30 import GENESIS, IdentityKeyRotation, RotationError


class RotationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "rotation.sqlite"
        self.registry = IdentityKeyRotation(self.path)
        self.first = b"a" * 32
        self.second = b"b" * 32
        self.third = b"c" * 32
        self.external = (0, GENESIS)
        self.allowed = True

    def publish(self):
        # SYNTHETIC independent anchor fixture: not a real external service.
        s = self.registry.inspect_local()
        self.external = (s["sequence"], s["head"])

    def prepare(self, old="root-0", new="root-1", public=None, **kwargs):
        current = self.registry.inspect_local()
        args = dict(
            old_key=old, new_key=new,
            public_key=self.first if public is None else public,
            expected_sequence=current["sequence"],
            expected_head=current["head"],
            verify_predecessor=lambda seq, head: (seq, head) == self.external,
            check_policy=lambda *_: self.allowed)
        args.update(kwargs)
        return self.registry.prepare(**args)

    def commit(self, old="root-0", new="root-1", public=None, **kwargs):
        current = self.registry.inspect_local()
        args = dict(
            old_key=old, new_key=new,
            public_key=self.first if public is None else public,
            expected_sequence=current["sequence"],
            expected_head=current["head"],
            verify_predecessor=lambda seq, head: (seq, head) == self.external,
            check_policy=lambda *_: self.allowed)
        args.update(kwargs)
        return self.registry.commit(**args)

    def complete_first(self):
        self.prepare()
        self.publish()
        result = self.commit()
        self.publish()
        return result

    def trust(self, key="root-1", fingerprint=None, **kwargs):
        from identity_key_rotation_v30 import _fingerprint
        opts = dict(
            verify_current_head=lambda seq, head: (seq, head) == self.external,
            check_external_key=lambda *_: True,
            expected_fingerprint=_fingerprint(
                self.first if fingerprint is None else fingerprint))
        opts.update(kwargs)
        return self.registry.trust_key(key, {}, **opts)

    def test_initial_state_denies(self):
        self.assertEqual(self.registry.inspect_local()["sequence"], 0)
        self.assertFalse(self.trust())

    def test_prepare_pending_non_authorizing(self):
        result = self.prepare()
        self.assertEqual(result["state"], "PENDING")
        self.assertEqual(result["authorization"], "DENY")
        self.assertEqual(result["release"], "HOLD")

    def test_pending_key_denies(self):
        self.prepare()
        self.publish()
        self.assertFalse(self.trust())

    def test_commit_uses_matching_prepare(self):
        result = self.complete_first()
        self.assertEqual(result["generation"], 1)
        self.assertEqual(self.registry.inspect_local()["active_key"], "root-1")

    def test_commit_without_prepare_denied(self):
        with self.assertRaisesRegex(RotationError, "NO_MATCHING_PREPARE"):
            self.commit()

    def test_unpublished_prepare_denies_commit(self):
        self.prepare()
        with self.assertRaisesRegex(RotationError, "UNTRUSTED_PREDECESSOR"):
            self.commit()

    def test_commit_wrong_fingerprint_denied(self):
        self.prepare()
        self.publish()
        with self.assertRaisesRegex(RotationError, "NO_MATCHING_PREPARE"):
            self.commit(public=self.second)

    def test_commit_wrong_key_denied(self):
        self.prepare()
        self.publish()
        with self.assertRaisesRegex(RotationError, "NO_MATCHING_PREPARE"):
            self.commit(new="impostor")

    def test_double_prepare_denied(self):
        self.prepare()
        self.publish()
        with self.assertRaisesRegex(RotationError, "INVALID_KEY_TRANSITION"):
            self.prepare(new="root-2", public=self.second)

    def test_stale_cas_denied(self):
        self.prepare()
        with self.assertRaisesRegex(RotationError, "STALE_TRANSITION"):
            self.commit(expected_sequence=0, expected_head=GENESIS)

    def test_publish_policy_denied(self):
        self.allowed = False
        with self.assertRaisesRegex(RotationError, "ROTATION_NOT_AUTHORIZED"):
            self.prepare()

    def test_publish_policy_nonboolean_denied(self):
        self.allowed = 1
        with self.assertRaisesRegex(RotationError, "ROTATION_NOT_AUTHORIZED"):
            self.prepare()

    def test_missing_anchor_denied(self):
        with self.assertRaisesRegex(RotationError, "EXTERNAL_TRUST_REQUIRED"):
            self.prepare(verify_predecessor=None)

    def test_wrong_anchor_denied(self):
        with self.assertRaisesRegex(RotationError, "UNTRUSTED_PREDECESSOR"):
            self.prepare(verify_predecessor=lambda *_: False)

    def test_anchor_nonboolean_denied(self):
        with self.assertRaisesRegex(RotationError, "UNTRUSTED_PREDECESSOR"):
            self.prepare(verify_predecessor=lambda *_: 1)

    def test_invalid_public_key_denied(self):
        with self.assertRaisesRegex(RotationError, "INVALID_PUBLIC_KEY"):
            self.prepare(public=b"tiny")

    def test_same_key_denied(self):
        with self.assertRaisesRegex(RotationError, "INVALID_KEY_TRANSITION"):
            self.prepare(old="root-1", new="root-1")

    def test_restart_preserves_pending(self):
        self.prepare()
        self.registry = IdentityKeyRotation(self.path)
        self.assertTrue(self.registry.inspect_local()["pending"])

    def test_restart_preserves_commit(self):
        self.complete_first()
        self.registry = IdentityKeyRotation(self.path)
        self.assertTrue(self.trust())
        self.assertEqual(self.registry.inspect_local()["generation"], 1)

    def test_key_active_requires_external_anchor(self):
        self.prepare()
        self.publish()
        self.commit()
        self.assertFalse(self.trust())
        self.publish()
        self.assertTrue(self.trust())

    def test_old_key_denied_after_commit(self):
        self.complete_first()
        self.assertFalse(self.trust(key="root-0"))
        self.assertTrue(self.trust(key="root-1"))

    def test_external_key_revocation_denied(self):
        self.complete_first()
        self.assertFalse(self.trust(check_external_key=lambda *_: False))

    def test_external_policy_truthy_nonboolean_denied(self):
        self.complete_first()
        self.assertFalse(self.trust(check_external_key=lambda *_: 1))

    def test_second_generation(self):
        self.complete_first()
        self.prepare(old="root-1", new="root-2", public=self.second)
        self.publish()
        self.commit(old="root-1", new="root-2", public=self.second)
        self.publish()
        self.assertEqual(self.registry.inspect_local()["generation"], 2)
        self.assertFalse(self.trust("root-1"))
        self.assertTrue(self.trust("root-2", fingerprint=self.second))

    def test_wrong_old_key_for_second_generation(self):
        self.complete_first()
        with self.assertRaisesRegex(RotationError, "INVALID_KEY_TRANSITION"):
            self.prepare(old="root-0", new="root-2", public=self.second)

    def test_no_reuse_retired_key(self):
        self.complete_first()
        self.prepare(old="root-1", new="root-2", public=self.second)
        self.publish()
        self.commit(old="root-1", new="root-2", public=self.second)
        self.publish()
        with self.assertRaisesRegex(RotationError, "INVALID_KEY_TRANSITION"):
            self.prepare(old="root-2", new="root-1", public=self.first)

    def test_local_mutation_trigger(self):
        self.prepare()
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE key_rotation_events SET new_key='evil'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM key_rotation_events")

    def test_corrupt_chain_detected(self):
        self.prepare()
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER rotation_no_update")
            db.execute("UPDATE key_rotation_events SET fingerprint=?", ("0"*64,))
        with self.assertRaisesRegex(RotationError, "CORRUPT_ROTATION_CHAIN"):
            self.registry.inspect_local()

    def test_no_private_key_api(self):
        self.assertFalse(hasattr(self.registry, "issue_private_key"))
        self.assertFalse(hasattr(self.registry, "sign"))
        self.assertFalse(hasattr(self.registry, "deploy"))

    def test_never_grant_production(self):
        result = self.complete_first()
        self.assertFalse(result["production_release_enabled"])


if __name__ == "__main__":
    unittest.main()
