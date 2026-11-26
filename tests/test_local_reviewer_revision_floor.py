"""Signed snapshot revision floor: no rollback/equivocation on one local DB."""
import base64
import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("revision_floor", ROOT / "tools" / "local_reviewer_revision_floor.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReviewerRevisionFloorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "revisions.sqlite"
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43))) # TEST ONLY
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(public).hexdigest()
        self.roots = {self.key_id: public}
        self.snapshot = {
            "schema_version": "0.1.0", "revision": 5,
            "reviewers": [{
                "reviewer_id": "reviewer-a", "key_fingerprint": "a" * 64,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z", "revoked": False,
            }]
        }

    def envelope(self, snapshot=None):
        snap = copy.deepcopy(self.snapshot if snapshot is None else snapshot)
        signed = module._reviewers.canonical(snap)
        signature = self.private.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00" + signed)
        return {"snapshot": snap, "issuer_key_id": self.key_id,
                "issuer_signature_b64": base64.b64encode(signature).decode()}

    def check(self, envelope=None, roots=None):
        result = module.observe(self.db, self.envelope() if envelope is None else envelope,
                                self.roots if roots is None else roots)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertIs(result["authorization_granted"], False)
        return result

    def test_first_signed_revision_recorded(self):
        self.assertTrue(self.check()["revision_recorded"])

    def test_same_revision_identical_is_idempotent(self):
        self.check()
        self.assertEqual(self.check()["reason"], "already-observed")

    def test_older_revision_quarantined(self):
        self.check()
        old = copy.deepcopy(self.snapshot)
        old["revision"] = 4
        self.assertEqual(self.check(self.envelope(old))["reason"], "registry-rollback")

    def test_same_revision_other_content_quarantined(self):
        self.check()
        changed = copy.deepcopy(self.snapshot)
        changed["reviewers"][0]["revoked"] = True
        self.assertEqual(self.check(self.envelope(changed))["reason"], "registry-equivocation")

    def test_newer_revocation_snapshot_recorded(self):
        self.check()
        snap = copy.deepcopy(self.snapshot)
        snap["revision"] = 6
        snap["reviewers"][0]["revoked"] = True
        self.assertTrue(self.check(self.envelope(snap))["revision_recorded"])

    def test_invalid_signature_does_not_create_db(self):
        env = self.envelope()
        env["snapshot"]["revision"] = 9
        self.assertEqual(self.check(env)["reason"], "invalid-snapshot-signature")
        self.assertFalse(self.db.exists())

    def test_unknown_root_does_not_create_db(self):
        self.assertEqual(self.check(roots={})["reason"], "invalid-snapshot-signature")
        self.assertFalse(self.db.exists())

    def test_revocation_downgrade_rejected(self):
        snap = copy.deepcopy(self.snapshot)
        snap["revision"] = 6
        snap["reviewers"][0]["revoked"] = True
        self.check(self.envelope(snap))
        self.assertEqual(self.check()["reason"], "registry-rollback")

    def test_missing_reviewers_quarantined(self):
        snap = copy.deepcopy(self.snapshot)
        snap["reviewers"] = []
        self.assertEqual(self.check(self.envelope(snap))["reason"], "no-reviewers")

    def test_invalid_db_path_rejected(self):
        with self.assertRaises(ValueError):
            module.observe(":memory:", self.envelope(), self.roots)


if __name__ == "__main__":
    unittest.main()
